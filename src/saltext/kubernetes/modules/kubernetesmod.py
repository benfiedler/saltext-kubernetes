# pylint: disable=raise-missing-from
"""
Module for handling kubernetes calls.

:optdepends:    - kubernetes Python client < 4.0
                - PyYAML < 6.0
:configuration: The k8s API settings are provided either in a pillar, in
    the minion's config file, or in master's config file::

        kubernetes.kubeconfig: '/path/to/kubeconfig'
        kubernetes.kubeconfig-data: '<base64 encoded kubeconfig content'
        kubernetes.context: 'context'

These settings can be overridden by adding `context and `kubeconfig` or
`kubeconfig_data` parameters when calling a function.

The data format for `kubernetes.kubeconfig-data` value is the content of
`kubeconfig` base64 encoded in one line.

Only `kubeconfig` or `kubeconfig-data` should be provided. In case both are
provided `kubeconfig` entry is preferred.

CLI Example:

.. code-block:: bash

    salt '*' kubernetes.nodes kubeconfig=/etc/salt/k8s/kubeconfig context=minikube

.. versionadded:: 2017.7.0
.. versionchanged:: 2019.2.0

.. warning::

    Configuration options changed in 2019.2.0. The following configuration options have been removed:

    - kubernetes.user
    - kubernetes.password
    - kubernetes.api_url
    - kubernetes.certificate-authority-data/file
    - kubernetes.client-certificate-data/file
    - kubernetes.client-key-data/file

    Please use now:

    - kubernetes.kubeconfig or kubernetes.kubeconfig-data
    - kubernetes.context

"""
import base64
import errno
import logging
import os.path
import signal
import sys
import tempfile
import time
from contextlib import contextmanager

import salt.utils.files
import salt.utils.platform
import salt.utils.templates
import salt.utils.yaml
from salt.exceptions import CommandExecutionError
from salt.exceptions import TimeoutError

# pylint: disable=import-error,no-name-in-module
try:
    import kubernetes  # pylint: disable=import-self
    import kubernetes.client
    from kubernetes.client.rest import ApiException
    from kubernetes.client import api_client
    from kubernetes.dynamic.exceptions import ResourceNotFoundError
    from urllib3.exceptions import HTTPError

    # pylint: disable=no-name-in-module
    try:
        # There is an API change in Kubernetes >= 2.0.0.
        from kubernetes.client import V1Deployment as AppsV1Deployment
        from kubernetes.client import V1DeploymentSpec as AppsV1DeploymentSpec
    except ImportError:
        from kubernetes.client import AppsV1Deployment, AppsV1DeploymentSpec
    # pylint: enable=no-name-in-module

    HAS_LIBS = True
except ImportError:
    HAS_LIBS = False
# pylint: enable=import-error,no-name-in-module

log = logging.getLogger(__name__)

__virtualname__ = "kubernetes"


def __virtual__():
    """
    Check dependencies
    """
    if HAS_LIBS:
        return __virtualname__

    return False, "python kubernetes library not found"


if not salt.utils.platform.is_windows():

    @contextmanager
    def _time_limit(seconds):
        def signal_handler(signum, frame):
            raise TimeoutError

        signal.signal(signal.SIGALRM, signal_handler)
        signal.alarm(seconds)
        try:
            yield
        finally:
            signal.alarm(0)

    POLLING_TIME_LIMIT = 30


def _setup_conn_old(**kwargs):
    """
    Setup kubernetes API connection singleton the old way
    """
    host = __salt__["config.option"]("kubernetes.api_url", "http://localhost:8080")
    username = __salt__["config.option"]("kubernetes.user")
    password = __salt__["config.option"]("kubernetes.password")
    ca_cert = __salt__["config.option"]("kubernetes.certificate-authority-data")
    client_cert = __salt__["config.option"]("kubernetes.client-certificate-data")
    client_key = __salt__["config.option"]("kubernetes.client-key-data")
    ca_cert_file = __salt__["config.option"]("kubernetes.certificate-authority-file")
    client_cert_file = __salt__["config.option"]("kubernetes.client-certificate-file")
    client_key_file = __salt__["config.option"]("kubernetes.client-key-file")

    # Override default API settings when settings are provided
    if "api_url" in kwargs:
        host = kwargs.get("api_url")

    if "api_user" in kwargs:
        username = kwargs.get("api_user")

    if "api_password" in kwargs:
        password = kwargs.get("api_password")

    if "api_certificate_authority_file" in kwargs:
        ca_cert_file = kwargs.get("api_certificate_authority_file")

    if "api_client_certificate_file" in kwargs:
        client_cert_file = kwargs.get("api_client_certificate_file")

    if "api_client_key_file" in kwargs:
        client_key_file = kwargs.get("api_client_key_file")

    if (
        kubernetes.client.configuration.host != host
        or kubernetes.client.configuration.user != username
        or kubernetes.client.configuration.password != password
    ):
        # Recreates API connection if settings are changed
        kubernetes.client.configuration.__init__()  # pylint: disable=unnecessary-dunder-call

    kubernetes.client.configuration.host = host
    kubernetes.client.configuration.user = username
    kubernetes.client.configuration.passwd = password

    if ca_cert_file:
        kubernetes.client.configuration.ssl_ca_cert = ca_cert_file
    elif ca_cert:
        with tempfile.NamedTemporaryFile(prefix="salt-kube-", delete=False) as ca:
            ca.write(base64.b64decode(ca_cert))
            kubernetes.client.configuration.ssl_ca_cert = ca.name
    else:
        kubernetes.client.configuration.ssl_ca_cert = None

    if client_cert_file:
        kubernetes.client.configuration.cert_file = client_cert_file
    elif client_cert:
        with tempfile.NamedTemporaryFile(prefix="salt-kube-", delete=False) as c:
            c.write(base64.b64decode(client_cert))
            kubernetes.client.configuration.cert_file = c.name
    else:
        kubernetes.client.configuration.cert_file = None

    if client_key_file:
        kubernetes.client.configuration.key_file = client_key_file
    elif client_key:
        with tempfile.NamedTemporaryFile(prefix="salt-kube-", delete=False) as k:
            k.write(base64.b64decode(client_key))
            kubernetes.client.configuration.key_file = k.name
    else:
        kubernetes.client.configuration.key_file = None
    return {}


# pylint: disable=no-member
def _setup_conn(**kwargs):
    """
    Setup kubernetes API connection singleton
    """
    kubeconfig = kwargs.get("kubeconfig") or __salt__["config.option"]("kubernetes.kubeconfig")
    kubeconfig_data = kwargs.get("kubeconfig_data") or __salt__["config.option"](
        "kubernetes.kubeconfig-data"
    )
    context = kwargs.get("context") or __salt__["config.option"]("kubernetes.context")

    if (kubeconfig_data and not kubeconfig) or (kubeconfig_data and kwargs.get("kubeconfig_data")):
        with tempfile.NamedTemporaryFile(prefix="salt-kubeconfig-", delete=False) as kcfg:
            kcfg.write(base64.b64decode(kubeconfig_data))
            kubeconfig = kcfg.name

    if not (kubeconfig and context):
        if kwargs.get("api_url") or __salt__["config.option"]("kubernetes.api_url"):
            try:
                return _setup_conn_old(**kwargs)
            except Exception:  # pylint: disable=broad-except
                raise CommandExecutionError(
                    "Old style kubernetes configuration is only supported up to"
                    " python-kubernetes 2.0.0"
                )
        else:
            raise CommandExecutionError(
                "Invalid kubernetes configuration. Parameter 'kubeconfig' and 'context'"
                " are required."
            )
    kubernetes.config.load_kube_config(config_file=kubeconfig, context=context)

    # The return makes unit testing easier
    return {"kubeconfig": kubeconfig, "context": context}


def _cleanup_old(**kwargs):
    try:
        ca = kubernetes.client.configuration.ssl_ca_cert
        cert = kubernetes.client.configuration.cert_file
        key = kubernetes.client.configuration.key_file
        if cert and os.path.exists(cert) and os.path.basename(cert).startswith("salt-kube-"):
            salt.utils.files.safe_rm(cert)
        if key and os.path.exists(key) and os.path.basename(key).startswith("salt-kube-"):
            salt.utils.files.safe_rm(key)
        if ca and os.path.exists(ca) and os.path.basename(ca).startswith("salt-kube-"):
            salt.utils.files.safe_rm(ca)
    except Exception:  # pylint: disable=broad-except
        pass


def _cleanup(**kwargs):
    if not kwargs:
        return _cleanup_old(**kwargs)

    if "kubeconfig" in kwargs:
        kubeconfig = kwargs.get("kubeconfig")
        if kubeconfig and os.path.basename(kubeconfig).startswith("salt-kubeconfig-"):
            try:
                os.unlink(kubeconfig)
            except OSError as err:
                if err.errno != errno.ENOENT:
                    log.exception(err)

def get_resource_def(apiVersion="v1", kind=None, **kwargs):
    """
    Get a resource definition using the dynamic client discoverer
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.dynamic.DynamicClient(
            api_client.ApiClient()
        )
        res = api_instance.resources.get(api_version=apiVersion, kind=kind)
        return res

    except (ApiException, HTTPError, ResourceNotFoundError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling DynamicClient->resources.get")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)

    return None


def ping(**kwargs):
    """
    Checks connections with the kubernetes API server.
    Returns True if the connection can be established, False otherwise.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.ping
    """
    status = True
    try:
        nodes(**kwargs)
    except CommandExecutionError:
        status = False

    return status


def nodes(**kwargs):
    """
    Return the names of the nodes composing the kubernetes cluster

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.nodes
        salt '*' kubernetes.nodes kubeconfig=/etc/salt/k8s/kubeconfig context=minikube
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.list_node()

        return [k8s_node["metadata"]["name"] for k8s_node in api_response.to_dict().get("items")]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->list_node")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def node(name, **kwargs):
    """
    Return the details of the node identified by the specified name

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.node name='minikube'
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.list_node()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->list_node")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)

    for k8s_node in api_response.items:
        if k8s_node.metadata.name == name:
            return k8s_node.to_dict()

    return None


def node_labels(name, **kwargs):
    """
    Return the labels of the node identified by the specified name

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.node_labels name="minikube"
    """
    match = node(name, **kwargs)

    if match is not None:
        return match["metadata"]["labels"]

    return {}


def node_add_label(node_name, label_name, label_value, **kwargs):
    """
    Set the value of the label identified by `label_name` to `label_value` on
    the node identified by the name `node_name`.
    Creates the label if not present.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.node_add_label node_name="minikube" \
            label_name="foo" label_value="bar"
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        body = {"metadata": {"labels": {label_name: label_value}}}
        api_response = api_instance.patch_node(node_name, body)
        return api_response
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->patch_node")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)

    return None


def node_remove_label(node_name, label_name, **kwargs):
    """
    Removes the label identified by `label_name` from
    the node identified by the name `node_name`.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.node_remove_label node_name="minikube" \
            label_name="foo"
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        body = {"metadata": {"labels": {label_name: None}}}
        api_response = api_instance.patch_node(node_name, body)
        return api_response
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->patch_node")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)

    return None


def namespaces(**kwargs):
    """
    Return the names of the available namespaces

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.namespaces
        salt '*' kubernetes.namespaces kubeconfig=/etc/salt/k8s/kubeconfig context=minikube
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.list_namespace()

        return [nms["metadata"]["name"] for nms in api_response.to_dict().get("items")]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->list_namespace")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def deployments(namespace="default", **kwargs):
    """
    Return a list of kubernetes deployments defined in the namespace

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.deployments
        salt '*' kubernetes.deployments namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.ExtensionsV1beta1Api()
        api_response = api_instance.list_namespaced_deployment(namespace)

        return [dep["metadata"]["name"] for dep in api_response.to_dict().get("items")]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling ExtensionsV1beta1Api->list_namespaced_deployment")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def services(namespace="default", **kwargs):
    """
    Return a list of kubernetes services defined in the namespace

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.services
        salt '*' kubernetes.services namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.list_namespaced_service(namespace)

        return [srv["metadata"]["name"] for srv in api_response.to_dict().get("items")]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->list_namespaced_service")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def service_accounts(namespace="default", **kwargs):
    """
    Return a list of kubernetes serviceaccounts defined in the namespace

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.service_accounts
        salt '*' kubernetes.service_accounts namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.list_namespaced_service_account(namespace)

        return [srv["metadata"]["name"] for srv in api_response.to_dict().get("items")]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->list_namespaced_service_account")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def pods(namespace="default", **kwargs):
    """
    Return a list of kubernetes pods defined in the namespace

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.pods
        salt '*' kubernetes.pods namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.list_namespaced_pod(namespace)

        return [pod["metadata"]["name"] for pod in api_response.to_dict().get("items")]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->list_namespaced_pod")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def secrets(namespace="default", **kwargs):
    """
    Return a list of kubernetes secrets defined in the namespace

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.secrets
        salt '*' kubernetes.secrets namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.list_namespaced_secret(namespace)

        return [secret["metadata"]["name"] for secret in api_response.to_dict().get("items")]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->list_namespaced_secret")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def configmaps(namespace="default", **kwargs):
    """
    Return a list of kubernetes configmaps defined in the namespace

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.configmaps
        salt '*' kubernetes.configmaps namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.list_namespaced_config_map(namespace)

        return [secret["metadata"]["name"] for secret in api_response.to_dict().get("items")]
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->list_namespaced_config_map")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def show_deployment(name, namespace="default", **kwargs):
    """
    Return the kubernetes deployment defined by name and namespace

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_deployment my-nginx default
        salt '*' kubernetes.show_deployment name=my-nginx namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.ExtensionsV1beta1Api()
        api_response = api_instance.read_namespaced_deployment(name, namespace)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling ExtensionsV1beta1Api->read_namespaced_deployment")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def show_service(name, namespace="default", **kwargs):
    """
    Return the kubernetes service defined by name and namespace

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_service my-nginx default
        salt '*' kubernetes.show_service name=my-nginx namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.read_namespaced_service(name, namespace)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->read_namespaced_service")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def show_service_account(name, namespace="default", **kwargs):
    """
    Return the kubernetes serviceaccount defined by name and namespace

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_service_account my-serviceacct default
        salt '*' kubernetes.show_service_account name=my-serviceacct namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.read_namespaced_service_account(name, namespace)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->read_namespaced_service_account")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def show_role(name, namespace="default", **kwargs):
    """
    Return the kubernetes role defined by name and namespace

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_role my-role default
        salt '*' kubernetes.show_role name=my-role namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.RbacAuthorizationV1Api()
        api_response = api_instance.read_namespaced_role(name, namespace)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->read_namespaced_role")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def show_cluster_role(name, **kwargs):
    """
    Return the kubernetes cluster role defined by name

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_cluster_role my-role
        salt '*' kubernetes.show_cluster_role name=my-role
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.RbacAuthorizationV1Api()
        api_response = api_instance.read_cluster_role(name)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->read_cluster_role")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def show_role_binding(name, namespace="default", **kwargs):
    """
    Return the kubernetes RoleBinding defined by name and namespace

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_role_binding my-rolebind default
        salt '*' kubernetes.show_role_binding name=my-rolebind namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.RbacAuthorizationV1Api()
        api_response = api_instance.read_namespaced_role_binding(name, namespace)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->read_namespaced_role_binding")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def show_cluster_role_binding(name, **kwargs):
    """
    Return the kubernetes ClusterRoleBinding defined by name

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_cluster_role_binding my-rolebind
        salt '*' kubernetes.show_cluster_role_binding name=my-rolebind
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.RbacAuthorizationV1Api()
        api_response = api_instance.read_cluster_role_binding(name)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->read_cluster_role_binding")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def show_pod(name, namespace="default", **kwargs):
    """
    Return POD information for a given pod name defined in the namespace

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_pod guestbook-708336848-fqr2x
        salt '*' kubernetes.show_pod guestbook-708336848-fqr2x namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.read_namespaced_pod(name, namespace)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->read_namespaced_pod")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def show_namespace(name, **kwargs):
    """
    Return information for a given namespace defined by the specified name

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_namespace kube-system
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.read_namespace(name)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->read_namespace")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def show_persistentvolume(name, **kwargs):
    """
    Return information for a PersistentVolume with the specified name

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_persistentvolume mypv
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.read_persistent_volume(name)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->read_persistent_volume")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def show_persistentvolumeclaim(name, namespace="default", **kwargs):
    """
    Return the kubernetes secret defined by name and namespace.
    The secrets can be decoded if specified by the user. Warning: this has
    security implications.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_persistentvolumeclaim mypvc mynamespace
        salt '*' kubernetes.show_persistentvolumeclaim name=mypvc namespace=mynamespace
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.read_namespaced_persistent_volume_claim(name, namespace)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->read_namespaced_persistent_volume_claim")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def show_secret(name, namespace="default", decode=False, **kwargs):
    """
    Return the kubernetes secret defined by name and namespace.
    The secrets can be decoded if specified by the user. Warning: this has
    security implications.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_secret confidential default
        salt '*' kubernetes.show_secret name=confidential namespace=default
        salt '*' kubernetes.show_secret name=confidential decode=True
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.read_namespaced_secret(name, namespace)

        if api_response.data and (decode or decode == "True"):
            for key in api_response.data:
                value = api_response.data[key]
                api_response.data[key] = base64.b64decode(value)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->read_namespaced_secret")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def show_configmap(name, namespace="default", **kwargs):
    """
    Return the kubernetes configmap defined by name and namespace.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_configmap game-config default
        salt '*' kubernetes.show_configmap name=game-config namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.read_namespaced_config_map(name, namespace)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception(
                "Exception when calling CoreV1Api->read_namespaced_config_map"
            )
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def show_namespaced_custom_obj(name, apiVersion, kind, namespace="default", **kwargs):
    """
    Return the kubernetes namespaced custom object defined by name and kind.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_namespaced_custom_obj myres v1 blah default
        salt '*' kubernetes.show_namespaced_custom_obj name=myres apiVersion=x kind=blah namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.dynamic.DynamicClient(
            api_client.ApiClient()
        )

        res_def = get_resource_def(apiVersion=apiVersion, kind=kind)

        if res_def is None:
            return None

        api_response = api_instance.get(resource=res_def,
                         name=name, namespace=namespace )

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception(
                "Exception when calling DynamicClient->get"
            )
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def show_custom_obj(name, apiVersion, kind, **kwargs):
    """
    Return the kubernetes custom object defined by name and kind.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.show_custom_obj v1 blah default
        salt '*' kubernetes.show_namespaced_custom_obj apiVersion=x kind=blah namespace=default
    """
    cfg = _setup_conn(**kwargs)
    try:
        api_instance = kubernetes.dynamic.DynamicClient(
            api_client.ApiClient()
        )

        res_def = get_resource_def(apiVersion=apiVersion, kind=kind)

        if res_def is None:
            return None

        api_response = api_instance.get(resource=res_def,
                         name=name)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception(
                "Exception when calling DynamicClient->get"
            )
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def delete_deployment(name, namespace="default", **kwargs):
    """
    Deletes the kubernetes deployment defined by name and namespace

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_deployment my-nginx
        salt '*' kubernetes.delete_deployment name=my-nginx namespace=default
    """
    cfg = _setup_conn(**kwargs)
    body = kubernetes.client.V1DeleteOptions(orphan_dependents=True)

    try:
        api_instance = kubernetes.client.ExtensionsV1beta1Api()
        api_response = api_instance.delete_namespaced_deployment(
            name=name, namespace=namespace, body=body
        )
        mutable_api_response = api_response.to_dict()
        if not salt.utils.platform.is_windows():
            try:
                with _time_limit(POLLING_TIME_LIMIT):
                    while show_deployment(name, namespace) is not None:
                        time.sleep(1)
                    else:  # pylint: disable=useless-else-on-loop
                        mutable_api_response["code"] = 200
            except TimeoutError:
                pass
        else:
            # Windows has not signal.alarm implementation, so we are just falling
            # back to loop-counting.
            for i in range(60):
                if show_deployment(name, namespace) is None:
                    mutable_api_response["code"] = 200
                    break
                else:
                    time.sleep(1)
        if mutable_api_response["code"] != 200:
            log.warning(
                "Reached polling time limit. Deployment is not yet "
                "deleted, but we are backing off. Sorry, but you'll "
                "have to check manually."
            )
        return mutable_api_response
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception(
                "Exception when calling ExtensionsV1beta1Api->delete_namespaced_deployment"
            )
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def delete_service(name, namespace="default", **kwargs):
    """
    Deletes the kubernetes service defined by name and namespace

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_service my-nginx default
        salt '*' kubernetes.delete_service name=my-nginx namespace=default
    """
    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.delete_namespaced_service(name=name, namespace=namespace)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->delete_namespaced_service")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def delete_service_account(name, namespace="default", **kwargs):
    """
    Deletes the kubernetes serviceaccount defined by name and namespace

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_service_account my-serviceaccount default
        salt '*' kubernetes.delete_service name=my-serviceaccount namespace=default
    """
    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.delete_namespaced_service_account(
            name=name, namespace=namespace
        )

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->delete_namespaced_service_account")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def delete_role(name, namespace="default", **kwargs):
    """
    Deletes the kubernetes role defined by name and namespace

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_role my-role default
        salt '*' kubernetes.delete_role name=my-role namespace=default
    """
    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.delete_namespaced_role(
            name=name, namespace=namespace
        )

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->delete_namespaced_role")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def delete_cluster_role(name, **kwargs):
    """
    Deletes the kubernetes cluster role defined by name

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_cluster_role my-role
        salt '*' kubernetes.delete_cluster_role name=my-role
    """
    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.delete_cluster_role(
            name=name
        )

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->delete_cluster_role")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def delete_role_binding(name, namespace="default", **kwargs):
    """
    Deletes the kubernetes RoleBinding defined by name and namespace

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_role_binding my-rolebind default
        salt '*' kubernetes.delete_role_binding name=my-rolebind namespace=default
    """
    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.delete_namespaced_role_binding(
            name=name, namespace=namespace
        )

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->delete_namespaced_role_binding")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def delete_cluster_role_binding(name, **kwargs):
    """
    Deletes the kubernetes ClusterRoleBinding defined by name

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_cluster_role_binding my-rolebind
        salt '*' kubernetes.delete_cluster_role_binding name=my-rolebind
    """
    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.delete_cluster_role_binding(
            name=name
        )

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->delete_cluster_role_binding")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def delete_pod(name, namespace="default", **kwargs):
    """
    Deletes the kubernetes pod defined by name and namespace

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_pod guestbook-708336848-5nl8c default
        salt '*' kubernetes.delete_pod name=guestbook-708336848-5nl8c namespace=default
    """
    cfg = _setup_conn(**kwargs)
    body = kubernetes.client.V1DeleteOptions(orphan_dependents=True)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.delete_namespaced_pod(name=name, namespace=namespace, body=body)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->delete_namespaced_pod")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def delete_namespace(name, **kwargs):
    """
    Deletes the kubernetes namespace defined by name

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_namespace salt
        salt '*' kubernetes.delete_namespace name=salt
    """
    cfg = _setup_conn(**kwargs)
    body = kubernetes.client.V1DeleteOptions(orphan_dependents=True)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.delete_namespace(name=name, body=body)
        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->delete_namespace")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def delete_persistentvolume(name, **kwargs):
    """
    Deletes the kubernetes PersistentVolume defined by name

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_persistentvolume mypv
        salt '*' kubernetes.delete_persistentvolume name=mypv
    """
    cfg = _setup_conn(**kwargs)
    body = kubernetes.client.V1DeleteOptions(orphan_dependents=True)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.delete_persistent_volume(name=name, body=body)
        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->delete_persistent_volume")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def delete_persistentvolumeclaim(name, namespace="default", **kwargs):
    """
    Deletes the kubernetes PersistentVolumeClaim defined by name and namespace

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_persistentvolumeclaim mypvc default
        salt '*' kubernetes.delete_persistentvolumeclaim name=mypvc namespace=default
    """
    cfg = _setup_conn(**kwargs)
    body = kubernetes.client.V1DeleteOptions(orphan_dependents=True)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.delete_namespaced_persistent_volume_claim(
            name=name, namespace=namespace, body=body
        )

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->delete_namespaced_persistent_volume_claim")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def delete_secret(name, namespace="default", **kwargs):
    """
    Deletes the kubernetes secret defined by name and namespace

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_secret confidential default
        salt '*' kubernetes.delete_secret name=confidential namespace=default
    """
    cfg = _setup_conn(**kwargs)
    body = kubernetes.client.V1DeleteOptions(orphan_dependents=True)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.delete_namespaced_secret(
            name=name, namespace=namespace, body=body
        )

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->delete_namespaced_secret")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def delete_configmap(name, namespace="default", **kwargs):
    """
    Deletes the kubernetes configmap defined by name and namespace

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.delete_configmap settings default
        salt '*' kubernetes.delete_configmap name=settings namespace=default
    """
    cfg = _setup_conn(**kwargs)
    body = kubernetes.client.V1DeleteOptions(orphan_dependents=True)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.delete_namespaced_config_map(
            name=name, namespace=namespace, body=body
        )

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception(
                "Exception when calling CoreV1Api->delete_namespaced_config_map"
            )
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)

def delete_namespaced_custom_obj(
    name,
    namespace="default",
    apiVersion="v1",
    kind=None,
    #context=context,
    saltenv="base",
    **kwargs,
):

    """
    Delete the kubernetes namespaced custom object specified by the user.
    """
    cfg = _setup_conn(**kwargs)

    api_instance = kubernetes.dynamic.DynamicClient(
        api_client.ApiClient()
    )

    res_def = get_resource_def(apiVersion=apiVersion, kind=kind)
    if res_def is None:
        return None

    cr_api = api_instance.resources.get(api_version=apiVersion, kind=kind)

    try:
        api_response = cr_api.delete(name=name, namespace=namespace)
        return {"data": api_response.to_dict() }
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling cr_api->delete")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def delete_custom_obj(
    name,
    apiVersion="v1",
    kind=None,
    #context=context,
    saltenv="base",
    **kwargs,
):

    """
    Delete the kubernetes custom object specified by the user.
    """
    cfg = _setup_conn(**kwargs)

    api_instance = kubernetes.dynamic.DynamicClient(
        api_client.ApiClient()
    )

    res_def = get_resource_def(apiVersion=apiVersion, kind=kind)
    if res_def is None:
        return None

    cr_api = api_instance.resources.get(api_version=apiVersion, kind=kind)

    try:
        api_response = cr_api.delete(name=name)
        return {"data": api_response.to_dict() }
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling cr_api->delete")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def create_deployment(
    name, namespace, metadata, spec, source, template, saltenv, **kwargs
):
    """
    Creates the kubernetes deployment as defined by the user.
    """
    body = __create_object_body(
        kind="Deployment",
        obj_class=AppsV1Deployment,
        spec_creator=__dict_to_deployment_spec,
        name=name,
        namespace=namespace,
        metadata=metadata,
        spec=spec,
        source=source,
        template=template,
        saltenv=saltenv,
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.ExtensionsV1beta1Api()
        api_response = api_instance.create_namespaced_deployment(namespace, body)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception(
                "Exception when calling "
                "ExtensionsV1beta1Api->create_namespaced_deployment"
            )
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def create_pod(name, namespace, metadata, spec, source, template, saltenv, **kwargs):
    """
    Creates the kubernetes deployment as defined by the user.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.create_pod *args
    """
    body = __create_object_body(
        kind="Pod",
        obj_class=kubernetes.client.V1Pod,
        spec_creator=__dict_to_pod_spec,
        name=name,
        namespace=namespace,
        metadata=metadata,
        spec=spec,
        source=source,
        template=template,
        saltenv=saltenv,
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.create_namespaced_pod(namespace, body)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->create_namespaced_pod")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def create_service(name, namespace, metadata, spec, source, template, saltenv, **kwargs):
    """
    Creates the kubernetes service as defined by the user.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.create_service *args
    """
    body = __create_object_body(
        kind="Service",
        obj_class=kubernetes.client.V1Service,
        spec_creator=__dict_to_service_spec,
        name=name,
        namespace=namespace,
        metadata=metadata,
        spec=spec,
        source=source,
        template=template,
        saltenv=saltenv,
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.create_namespaced_service(namespace, body)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->create_namespaced_service")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def create_service_account(
    name,
    metadata,
    saltenv,
    namespace="default",
    automount_service_account_token=None,
    image_pull_secrets=None,
    secrets=None,
    **kwargs
):
    """
    Creates the kubernetes serviceaccount as defined by the user.
    """
    body = kubernetes.client.V1ServiceAccount(
        metadata=__dict_to_object_meta(name, namespace, metadata),
        automount_service_account_token=automount_service_account_token,
        image_pull_secrets=image_pull_secrets,
        secrets=secrets,
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.create_namespaced_service_account(namespace, body)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->create_namespaced_service_account")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def create_role(
    name,
    namespace,
    metadata,
    rules,
    saltenv,
    **kwargs
):
    """
    Creates the kubernetes role as defined by the user.
    """
    body = kubernetes.client.V1Role(
        metadata=__dict_to_object_meta(name, namespace, metadata),
        rules=rules,
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.RbacAuthorizationV1Api()
        api_response = api_instance.create_namespaced_role(namespace, body)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling RbacAuthorizationV1Api->create_namespaced_role")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def create_cluster_role(
    name,
    metadata,
    rules,
    saltenv,
    **kwargs
):
    """
    Creates the kubernetes cluster role as defined by the user.
    """
    body = kubernetes.client.V1ClusterRole(
        metadata=__dict_to_object_meta(name, None, metadata),
        rules=rules,
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.RbacAuthorizationV1Api()
        api_response = api_instance.create_cluster_role(body)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling RbacAuthorizationV1Api->create_cluster_role")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def create_role_binding(
    name,
    namespace,
    metadata,
    role_ref,
    subjects,
    saltenv,
    **kwargs
):
    """
    Creates the kubernetes RoleBinding as defined by the user.
    """
    body = kubernetes.client.V1RoleBinding(
        metadata=__dict_to_object_meta(name, namespace, metadata),
        role_ref=role_ref,
        subjects=subjects,
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.RbacAuthorizationV1Api()
        api_response = api_instance.create_namespaced_role_binding(namespace, body)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling RbacAuthorizationV1Api->create_namespaced_role_binding")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def create_cluster_role_binding(
    name,
    metadata,
    role_ref,
    subjects,
    saltenv,
    **kwargs
):
    """
    Creates the kubernetes ClusterRoleBinding as defined by the user.
    """
    body = kubernetes.client.V1ClusterRoleBinding(
        metadata=__dict_to_object_meta(name, None, metadata),
        role_ref=role_ref,
        subjects=subjects,
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.RbacAuthorizationV1Api()
        api_response = api_instance.create_cluster_role_binding(body)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling RbacAuthorizationV1Api->create_cluster_role_binding")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def create_secret(
    name,
    namespace="default",
    data=None,
    metadata=None,
    stringData=None,
    source=None,
    template=None,
    context=None,
    type="Opaque",
    saltenv="base",
    **kwargs
):
    """
    Creates the kubernetes secret as defined by the user.

    CLI Example:

    .. code-block:: bash

        salt 'minion1' kubernetes.create_secret \
            passwords default '{"db": "letmein"}'

        salt 'minion2' kubernetes.create_secret \
            name=passwords namespace=default data='{"db": "letmein"}'
    """
    if source:
        data = __read_and_render_yaml_file(source, template, saltenv, context)
    elif data is None:
        data = {}

    data = __enforce_only_strings_dict(data)

    if stringData is not None:
        stringData = __enforce_only_strings_dict(data)

    body = kubernetes.client.V1Secret(
        metadata=__dict_to_object_meta(name, namespace, metadata), data=data,
            string_data=stringData, type=type,
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.create_namespaced_secret(namespace, body)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->create_namespaced_secret")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def create_configmap(name, namespace, data, source=None, template=None, saltenv="base", **kwargs):
    """
    Creates the kubernetes configmap as defined by the user.

    CLI Example:

    .. code-block:: bash

        salt 'minion1' kubernetes.create_configmap \
            settings default '{"example.conf": "# example file"}'

        salt 'minion2' kubernetes.create_configmap \
            name=settings namespace=default data='{"example.conf": "# example file"}'
    """
    if source:
        data = __read_and_render_yaml_file(source, template, saltenv)
    elif data is None:
        data = {}

    data = __enforce_only_strings_dict(data)

    body = kubernetes.client.V1ConfigMap(
        metadata=__dict_to_object_meta(name, namespace, metadata), data=data
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.create_namespaced_config_map(namespace, body)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->create_namespaced_config_map")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def create_namespace(name, **kwargs):
    """
    Creates a namespace with the specified name.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.create_namespace salt
        salt '*' kubernetes.create_namespace name=salt
    """

    meta_obj = kubernetes.client.V1ObjectMeta(name=name)
    body = kubernetes.client.V1Namespace(metadata=meta_obj)
    body.metadata.name = name

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.create_namespace(body)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->create_namespace")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def create_persistentvolume(
    name,
    metadata=None,
    spec=None,
    status=None,
    saltenv="base",
    **kwargs
):
    """
    Creates a PersistentVolume with the specified name.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.create_persistentvolume mypv
        salt '*' kubernetes.create_persistentvolume name=mypv spec={'volumeMode': 'Filesystem'}
    """

    body = kubernetes.client.V1PersistentVolume(
        metadata=__dict_to_object_meta(name, None, metadata),
        spec=spec,
        status=status,
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.create_persistent_volume(body)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->create_persistent_volume")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def create_persistentvolumeclaim(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    status=None,
    saltenv="base",
    **kwargs
):

    """
    Creates the kubernetes PersistentVolumeClaim as defined by the user.
    """
    body = kubernetes.client.V1PersistentVolumeClaim(
        metadata=__dict_to_object_meta(name, namespace, metadata),
        spec=spec,
        status=status,
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.create_namespaced_persistent_volume_claim(namespace, body)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->create_namespaced_persistent_volume_claim")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def create_namespaced_custom_obj(
    name,
    namespace="default",
    apiVersion="v1",
    kind=None,
    metadata=None,
    spec=None,
    status=None,
    source=None,
    template=None,
    #context=context,
    saltenv="base",
    **kwargs,
):

    """
    Creates the kubernetes custom object as defined by the user.
    """
    cfg = _setup_conn(**kwargs)

    api_instance = kubernetes.dynamic.DynamicClient(
        api_client.ApiClient()
    )

    res_def = get_resource_def(apiVersion=apiVersion, kind=kind)
    if res_def is None:
        return None

    res_manifest = {
            "apiVersion": apiVersion,
            "kind": kind,
            "metadata": __dict_to_object_meta(name, namespace, metadata).to_dict(),
            "spec": spec,
    }
    cr_api = api_instance.resources.get(api_version=apiVersion, kind=kind)

    try:
        api_response = cr_api.create(body=res_manifest, namespace=namespace)
        return {"data": api_response.to_dict() }
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling cr_api->create")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def create_custom_obj(
    name,
    apiVersion="v1",
    kind=None,
    metadata=None,
    spec=None,
    status=None,
    source=None,
    template=None,
    #context=context,
    saltenv="base",
    **kwargs,
):

    """
    Creates the cluster-wide kubernetes custom object as defined by the user.
    """
    cfg = _setup_conn(**kwargs)

    api_instance = kubernetes.dynamic.DynamicClient(
        api_client.ApiClient()
    )

    res_def = get_resource_def(apiVersion=apiVersion, kind=kind)

    if res_def is None:
        return None

    meta = __dict_to_object_meta(name, None, metadata).to_dict()

    res_manifest = {
            "apiVersion": apiVersion,
            "kind": kind,
            "metadata": meta,
            "spec": spec,
    }

    cr_api = api_instance.resources.get(api_version=apiVersion, kind=kind)

    try:
        api_response = cr_api.create(body=res_manifest)
        return {"data": api_response.to_dict() }
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling cr_api->create")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def replace_deployment(
    name,
    metadata,
    spec,
    source,
    template,
    saltenv,
    rebuild=False,
    namespace="default",
    **kwargs
):
    """
    Replaces an existing deployment with a new one defined by name and
    namespace, having the specified metadata and spec.
    """
    body = __create_object_body(
        kind="Deployment",
        obj_class=AppsV1Deployment,
        spec_creator=__dict_to_deployment_spec,
        name=name,
        namespace=namespace,
        metadata=metadata,
        spec=spec,
        source=source,
        template=template,
        saltenv=saltenv,
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.ExtensionsV1beta1Api()
        api_response = api_instance.replace_namespaced_deployment(name, namespace, body)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception(
                "Exception when calling ExtensionsV1beta1Api->replace_namespaced_deployment"
            )
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def replace_service(
    name,
    metadata,
    spec,
    source,
    template,
    old_service,
    saltenv,
    rebuild=False,
    namespace="default",
    **kwargs
):
    """
    Replaces an existing service with a new one defined by name and namespace,
    having the specificed metadata and spec.

    CLI Example:

    .. code-block:: bash

        salt '*' kubernetes.replace_service *args
    """
    body = __create_object_body(
        kind="Service",
        obj_class=kubernetes.client.V1Service,
        spec_creator=__dict_to_service_spec,
        name=name,
        namespace=namespace,
        metadata=metadata,
        spec=spec,
        source=source,
        template=template,
        saltenv=saltenv,
    )

    # Some attributes have to be preserved
    # otherwise exceptions will be thrown
    body.spec.cluster_ip = old_service["spec"]["cluster_ip"]
    body.metadata.resource_version = old_service["metadata"]["resource_version"]

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.replace_namespaced_service(name, namespace, body)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception(
                "Exception when calling CoreV1Api->replace_namespaced_service"
            )
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def replace_service_account(
    name,
    metadata,
    saltenv,
    namespace,
    automount_service_account_token,
    image_pull_secrets,
    secrets,
    old_service_account,
    rebuild=False,
    **kwargs
):
    """
    Replaces an existing service account with a new one defined by name and
    namespace, having the specified metadata and options.
    """

    body = kubernetes.client.V1ServiceAccount(
        metadata=__dict_to_object_meta(name, namespace, metadata),
        automount_service_account_token=automount_service_account_token,
        image_pull_secrets=image_pull_secrets,
        secrets=secrets,
    )

    # Some attributes have to be preserved
    # otherwise exceptions will be thrown
    body.metadata.resource_version = old_service_account["metadata"]["resource_version"]

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.replace_namespaced_service_account(name, namespace, body)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception(
                "Exception when calling CoreV1Api->replace_namespaced_service_account"
            )
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def replace_role(
    name,
    namespace,
    metadata,
    rules,
    old_role,
    saltenv,
    **kwargs
):
    """
    Replaces an existing role with a new one defined by name and
    namespace, having the specified metadata and rules.
    """

    body = kubernetes.client.V1Role(
        metadata=__dict_to_object_meta(name, namespace, metadata),
        rules=rules,
    )

    # Some attributes have to be preserved
    # otherwise exceptions will be thrown
    body.metadata.resource_version = old_role["metadata"]["resource_version"]

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.RbacAuthorizationV1Api()
        api_response = api_instance.replace_namespaced_role(name, namespace, body)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception(
                "Exception when calling RbacAuthorizationV1Api->replace_namespaced_role"
            )
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def replace_cluster_role(
    name,
    metadata,
    rules,
    old_role,
    saltenv,
    **kwargs
):
    """
    Replaces an existing role with a new one defined by name and
    namespace, having the specified metadata and rules.
    """

    body = kubernetes.client.V1ClusterRole(
        metadata=__dict_to_object_meta(name, None, metadata),
        rules=rules,
    )

    # Some attributes have to be preserved
    # otherwise exceptions will be thrown
    body.metadata.resource_version = old_role["metadata"]["resource_version"]

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.RbacAuthorizationV1Api()
        api_response = api_instance.replace_cluster_role(name, body)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception(
                "Exception when calling RbacAuthorizationV1Api->replace_cluster_role"
            )
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def replace_role_binding(
    name,
    namespace,
    metadata,
    role_ref,
    subjects,
    old_role_binding,
    saltenv,
    **kwargs
):
    """
    Replaces an existing RoleBinding with a new one defined by name and
    namespace, having the specified metadata and roleref and subjects.
    """

    body = kubernetes.client.V1RoleBinding(
        metadata=__dict_to_object_meta(name, namespace, metadata),
        role_ref=role_ref,
        subjects=subjects,
    )

    # Some attributes have to be preserved
    # otherwise exceptions will be thrown
    body.metadata.resource_version = old_role_binding["metadata"]["resource_version"]

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.RbacAuthorizationV1Api()
        api_response = api_instance.replace_namespaced_role_binding(name, namespace, body)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception(
                "Exception when calling RbacAuthorizationV1Api->replace_namespaced_role_binding"
            )
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def replace_cluster_role_binding(
    name,
    metadata,
    role_ref,
    subjects,
    old_role_binding,
    saltenv,
    **kwargs
):
    """
    Replaces an existing ClusterRoleBinding with a new one defined by name and
    namespace, having the specified metadata and roleref and subjects.
    """

    body = kubernetes.client.V1ClusterRoleBinding(
        metadata=__dict_to_object_meta(name, None, metadata),
        role_ref=role_ref,
        subjects=subjects,
    )

    # Some attributes have to be preserved
    # otherwise exceptions will be thrown
    body.metadata.resource_version = old_role_binding["metadata"]["resource_version"]

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.RbacAuthorizationV1Api()
        api_response = api_instance.replace_cluster_role_binding(name, body)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception(
                "Exception when calling RbacAuthorizationV1Api->replace_cluster_role_binding"
            )
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def replace_secret(
    name,
    data,
    stringData=None,
    metadata=None,
    source=None,
    template=None,
    context=None,
    type="Opaque",
    rebuild=False,
    saltenv="base",
    namespace="default",
    **kwargs
):
    """
    Replaces an existing secret with a new one defined by name and namespace,
    having the specified data.

    CLI Example:

    .. code-block:: bash

        salt 'minion1' kubernetes.replace_secret \
            name=passwords data='{"db": "letmein"}'

        salt 'minion2' kubernetes.replace_secret \
            name=passwords namespace=saltstack data='{"db": "passw0rd"}'
    """
    if source:
        data = __read_and_render_yaml_file(source, template, saltenv)
    elif data is None:
        data = {}

    data = __enforce_only_strings_dict(data)

    body = kubernetes.client.V1Secret(
        metadata=__dict_to_object_meta(name, namespace, metadata), data=data,
        string_data=stringData, type=type,
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.replace_namespaced_secret(name, namespace, body)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling CoreV1Api->replace_namespaced_secret")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def replace_configmap(
    name,
    data,
    metadata=None,
    source=None,
    template=None,
    context=None,
    rebuild=False,
    saltenv="base",
    namespace="default",
    **kwargs
):
    """
    Replaces an existing configmap with a new one defined by name and
    namespace with the specified data.

    CLI Example:

    .. code-block:: bash

        salt 'minion1' kubernetes.replace_configmap \
            settings default '{"example.conf": "# example file"}'

        salt 'minion2' kubernetes.replace_configmap \
            name=settings namespace=default data='{"example.conf": "# example file"}'
    """
    if source:
        data = __read_and_render_yaml_file(source, template, saltenv)

    data = __enforce_only_strings_dict(data)

    body = kubernetes.client.V1ConfigMap(
        metadata=__dict_to_object_meta(name, namespace, metadata), data=data
    )

    cfg = _setup_conn(**kwargs)

    try:
        api_instance = kubernetes.client.CoreV1Api()
        api_response = api_instance.replace_namespaced_config_map(name, namespace, body)

        return api_response.to_dict()
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception(
                "Exception when calling CoreV1Api->replace_namespaced_configmap"
            )
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)

def replace_namespaced_custom_obj(
    name,
    namespace="default",
    apiVersion="v1",
    kind=None,
    metadata=None,
    spec=None,
    status=None,
    source=None,
    template=None,
    #context=context,
    saltenv="base",
    **kwargs,
):

    """
    Replaces a kubernetes namespaced custom object as defined by the user.
    """
    cfg = _setup_conn(**kwargs)

    api_instance = kubernetes.dynamic.DynamicClient(
        api_client.ApiClient()
    )

    res_def = get_resource_def(apiVersion=apiVersion, kind=kind)

    if res_def is None:
        return None

    # https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#concurrency-control-and-consistency
    # we have to query + extract the existing resourceVersion or get error 422
    existing = api_instance.get(resource=res_def,
                                name=name, namespace=namespace )

    meta = __dict_to_object_meta(name, namespace, metadata).to_dict()
    meta["resourceVersion"] = existing.to_dict()["metadata"]["resourceVersion"]

    res_manifest = {
            "apiVersion": apiVersion,
            "kind": kind,
            "metadata": meta,
            "spec": spec,
    }

    cr_api = api_instance.resources.get(api_version=apiVersion, kind=kind)

    try:
        api_response = cr_api.replace(body=res_manifest, namespace=namespace)

        return {"data": api_response.to_dict() }
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling cr_api->replace")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def replace_custom_obj(
    name,
    apiVersion="v1",
    kind=None,
    metadata=None,
    spec=None,
    status=None,
    source=None,
    template=None,
    #context=context,
    saltenv="base",
    **kwargs,
):

    """
    Replaces a kubernetes custom object as defined by the user.
    """
    cfg = _setup_conn(**kwargs)

    api_instance = kubernetes.dynamic.DynamicClient(
        api_client.ApiClient()
    )

    res_def = get_resource_def(apiVersion=apiVersion, kind=kind)

    if res_def is None:
        return None

    # https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#concurrency-control-and-consistency
    # we have to query + extract the existing resourceVersion or get error 422
    existing = api_instance.get(resource=res_def,
                                name=name)

    meta = __dict_to_object_meta(name, None, metadata).to_dict()
    meta["resourceVersion"] = existing.to_dict()["metadata"]["resourceVersion"]

    res_manifest = {
            "apiVersion": apiVersion,
            "kind": kind,
            "metadata": meta,
            "spec": spec,
    }

    cr_api = api_instance.resources.get(api_version=apiVersion, kind=kind)

    try:
        api_response = cr_api.replace(body=res_manifest)

        return {"data": api_response.to_dict() }
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            log.exception("Exception when calling cr_api->replace")
            raise CommandExecutionError(exc)
    finally:
        _cleanup(**cfg)


def __create_object_body(
    kind,
    obj_class,
    spec_creator,
    name,
    namespace,
    metadata,
    spec,
    source,
    template,
    saltenv,
):
    """
    Create a Kubernetes Object body instance.
    """
    if source:
        src_obj = __read_and_render_yaml_file(source, template, saltenv)
        if (
            not isinstance(src_obj, dict)
            or "kind" not in src_obj
            or src_obj["kind"] != kind
        ):
            raise CommandExecutionError(
                f"The source file should define only a {kind} object"
            )

        if "metadata" in src_obj:
            metadata = src_obj["metadata"]
        if "spec" in src_obj:
            spec = src_obj["spec"]

    return obj_class(
        metadata=__dict_to_object_meta(name, namespace, metadata),
        spec=spec_creator(spec),
    )


def __read_and_render_yaml_file(source, template, saltenv, context=None):
    """
    Read a yaml file and, if needed, renders that using the specifieds
    templating. Returns the python objects defined inside of the file.
    """
    sfn = __salt__["cp.cache_file"](source, saltenv)
    if not sfn:
        raise CommandExecutionError(f"Source file '{source}' not found")

    with salt.utils.files.fopen(sfn, "r") as src:
        contents = src.read()

        if template:
            if template in salt.utils.templates.TEMPLATE_REGISTRY:
                # TODO: should we allow user to set also `context` like  # pylint: disable=fixme
                # `file.managed` does?
                # Apply templating
                data = salt.utils.templates.TEMPLATE_REGISTRY[template](
                    contents,
                    from_str=True,
                    to_str=True,
                    saltenv=saltenv,
                    context=context,
                    grains=__grains__,
                    pillar=__pillar__,
                    salt=__salt__,
                    opts=__opts__,
                )

                if not data["result"]:
                    # Failed to render the template
                    raise CommandExecutionError(
                        f"Failed to render file path with error: {data['data']}"
                    )

                contents = data["data"].encode("utf-8")
            else:
                raise CommandExecutionError(
                    f"Unknown template specified: {template}"
                )

        return salt.utils.yaml.safe_load(contents)


def __dict_to_object_meta(name, namespace, metadata):
    """
    Converts a dictionary into kubernetes ObjectMetaV1 instance.
    """
    meta_obj = kubernetes.client.V1ObjectMeta()
    if metadata is None:
        metadata = {}

    if namespace is not None:
        meta_obj.namespace = namespace

    # Replicate `kubectl [create|replace|apply] --record`
    if "annotations" not in metadata:
        metadata["annotations"] = {}
    if "kubernetes.io/change-cause" not in metadata["annotations"]:
        metadata["annotations"]["kubernetes.io/change-cause"] = " ".join(sys.argv)

    for key, value in metadata.items():
        if hasattr(meta_obj, key):
            setattr(meta_obj, key, value)

    if meta_obj.name != name:
        log.warning(
            "The object already has a name attribute, overwriting it with "
            "the one defined inside of salt"
        )
        meta_obj.name = name

    return meta_obj


def __dict_to_deployment_spec(spec):
    """
    Converts a dictionary into kubernetes AppsV1DeploymentSpec instance.
    """
    spec_obj = AppsV1DeploymentSpec(template=spec.get("template", ""))
    for key, value in spec.items():
        if hasattr(spec_obj, key):
            setattr(spec_obj, key, value)

    return spec_obj


def __dict_to_pod_spec(spec):
    """
    Converts a dictionary into kubernetes V1PodSpec instance.
    """
    spec_obj = kubernetes.client.V1PodSpec()
    for key, value in spec.items():
        if hasattr(spec_obj, key):
            setattr(spec_obj, key, value)

    return spec_obj


def __dict_to_service_spec(spec):
    """
    Converts a dictionary into kubernetes V1ServiceSpec instance.
    """
    spec_obj = kubernetes.client.V1ServiceSpec()
    for key, value in spec.items():  # pylint: disable=too-many-nested-blocks
        if key == "ports":
            spec_obj.ports = []
            for port in value:
                kube_port = kubernetes.client.V1ServicePort()
                if isinstance(port, dict):
                    for port_key, port_value in port.items():
                        if hasattr(kube_port, port_key):
                            setattr(kube_port, port_key, port_value)
                else:
                    kube_port.port = port
                spec_obj.ports.append(kube_port)
        elif hasattr(spec_obj, key):
            setattr(spec_obj, key, value)

    return spec_obj


def __enforce_only_strings_dict(dictionary):
    """
    Returns a dictionary that has string keys and values.
    """
    ret = {}

    for key, value in dictionary.items():
        ret[str(key)] = str(value)

    return ret
