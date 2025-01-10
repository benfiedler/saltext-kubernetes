"""
Manage kubernetes resources as salt states
==========================================

NOTE: This module requires the proper pillar values set. See
salt.modules.kubernetesmod for more information.

.. warning::

    Configuration options will change in 2019.2.0.

The kubernetes module is used to manage different kubernetes resources.


.. code-block:: yaml

    my-nginx:
      kubernetes.deployment_present:
        - namespace: default
          metadata:
            app: frontend
          spec:
            replicas: 1
            template:
              metadata:
                labels:
                  run: my-nginx
              spec:
                containers:
                - name: my-nginx
                  image: nginx
                  ports:
                  - containerPort: 80

    my-mariadb:
      kubernetes.deployment_absent:
        - namespace: default

    # kubernetes deployment as specified inside of
    # a file containing the definition of the the
    # deployment using the official kubernetes format
    redis-master-deployment:
      kubernetes.deployment_present:
        - name: redis-master
        - source: salt://k8s/redis-master-deployment.yml
      require:
        - pip: kubernetes-python-module

    # kubernetes service as specified inside of
    # a file containing the definition of the the
    # service using the official kubernetes format
    redis-master-service:
      kubernetes.service_present:
        - name: redis-master
        - source: salt://k8s/redis-master-service.yml
      require:
        - kubernetes.deployment_present: redis-master

    # kubernetes deployment as specified inside of
    # a file containing the definition of the the
    # deployment using the official kubernetes format
    # plus some jinja directives
     nginx-source-template:
      kubernetes.deployment_present:
        - source: salt://k8s/nginx.yml.jinja
        - template: jinja
      require:
        - pip: kubernetes-python-module


    # Kubernetes secret
    k8s-secret:
      kubernetes.secret_present:
        - name: top-secret
          data:
            key1: value1
            key2: value2
            key3: value3

.. versionadded:: 2017.7.0
"""
import copy
import logging

log = logging.getLogger(__name__)

__virtualname__ = "kubernetes"


def __virtual__():
    """
    Only load if the kubernetes module is available in __salt__
    """
    if "kubernetes.ping" in __salt__:
        return True
    return (False, "kubernetes module could not be loaded")


def _error(ret, err_msg):
    """
    Helper function to propagate errors to
    the end user.
    """
    ret["result"] = False
    ret["comment"] = err_msg
    return ret


def deployment_absent(name, namespace="default", **kwargs):
    """
    Ensures that the named deployment is absent from the given namespace.

    name
        The name of the deployment

    namespace
        The name of the namespace
    """

    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    deployment = __salt__["kubernetes.show_deployment"](name, namespace, **kwargs)

    if deployment is None:
        ret["result"] = True if not __opts__["test"] else None
        ret["comment"] = "The deployment does not exist"
        return ret

    if __opts__["test"]:
        ret["comment"] = "The deployment is going to be deleted"
        ret["result"] = None
        return ret

    res = __salt__["kubernetes.delete_deployment"](name, namespace, **kwargs)
    if res["code"] == 200:
        ret["result"] = True
        ret["changes"] = {"kubernetes.deployment": {"new": "absent", "old": "present"}}
        ret["comment"] = res["message"]
    else:
        ret["comment"] = f"Something went wrong, response: {res}"

    return ret


def deployment_present(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source="",
    template="",
    context=None,
    rebuild=False,
    **kwargs
):
    """
    Ensures that the named deployment is present inside of the specified
    namespace with the given metadata and spec.
    If the deployment exists it will be replaced.

    name
        The name of the deployment.

    namespace
        The namespace holding the deployment. The 'default' one is going to be
        used unless a different one is specified.

    metadata
        The metadata of the deployment object.

    spec
        The spec of the deployment object.

    source
        A file containing the definition of the deployment (metadata and
        spec) in the official kubernetes format.

    template
        Template engine to be used to render the source file.

    context
        Context variables passed to the template

    rebuild
        Delete and recreate the resource if a non-fatal error is encountered
    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    if (metadata or spec) and source:
        return _error(ret, "'source' cannot be used in combination with 'metadata' or 'spec'")

    if metadata is None:
        metadata = {}

    if spec is None:
        spec = {}

    deployment = __salt__["kubernetes.show_deployment"](name, namespace, **kwargs)

    if deployment is None:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The deployment is going to be created"
            return ret
        res = __salt__["kubernetes.create_deployment"](
            name=name,
            namespace=namespace,
            metadata=metadata,
            spec=spec,
            source=source,
            template=template,
            context=context,
            saltenv=__env__,
            **kwargs,
        )
        ret["changes"][f"{namespace}.{name}"] = {"old": {}, "new": res}
    else:
        if __opts__["test"]:
            ret["result"] = None
            return ret

        # TODO: improve checks  # pylint: disable=fixme
        log.info("Forcing the recreation of the deployment")
        ret["comment"] = "The deployment is already present. Forcing recreation"
        res = __salt__["kubernetes.replace_deployment"](
            name=name,
            namespace=namespace,
            metadata=metadata,
            spec=spec,
            source=source,
            template=template,
            context=context,
            saltenv=__env__,
            rebuild=rebuild,
            **kwargs
        )

    ret["changes"] = {"metadata": metadata, "spec": spec}
    ret["result"] = True
    return ret


def service_present(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source="",
    template="",
    context=None,
    rebuild=False,
    **kwargs
):
    """
    Ensures that the named service is present inside of the specified namespace
    with the given metadata and spec.
    If the deployment exists it will be replaced.

    name
        The name of the service.

    namespace
        The namespace holding the service. The 'default' one is going to be
        used unless a different one is specified.

    metadata
        The metadata of the service object.

    spec
        The spec of the service object.

    source
        A file containing the definition of the service (metadata and
        spec) in the official kubernetes format.

    template
        Template engine to be used to render the source file.

    context
        Context variables passed to the template

    rebuild
        Delete and recreate the resource if a non-fatal error is encountered
    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    if (metadata or spec) and source:
        return _error(ret, "'source' cannot be used in combination with 'metadata' or 'spec'")

    if metadata is None:
        metadata = {}

    if spec is None:
        spec = {}

    service = __salt__["kubernetes.show_service"](name, namespace, **kwargs)

    if service is None:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The service is going to be created"
            return ret
        res = __salt__["kubernetes.create_service"](
            name=name,
            namespace=namespace,
            metadata=metadata,
            spec=spec,
            source=source,
            template=template,
            context=context,
            saltenv=__env__,
            **kwargs,
        )
        ret["changes"][f"{namespace}.{name}"] = {"old": {}, "new": res}
    else:
        if __opts__["test"]:
            ret["result"] = None
            return ret

        # TODO: improve checks  # pylint: disable=fixme
        log.info("Forcing the recreation of the service")
        ret["comment"] = "The service is already present. Forcing recreation"
        res = __salt__["kubernetes.replace_service"](
            name=name,
            namespace=namespace,
            metadata=metadata,
            spec=spec,
            source=source,
            template=template,
            context=context,
            old_service=service,
            saltenv=__env__,
            rebuild=rebuild,
            **kwargs
        )

    ret["changes"] = {"metadata": metadata, "spec": spec}
    ret["result"] = True
    return ret


def service_absent(name, namespace="default", **kwargs):
    """
    Ensures that the named service is absent from the given namespace.

    name
        The name of the service

    namespace
        The namespace holding the service. The 'default' one is going
        to be used unless a different one is specified.

    """

    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    service = __salt__["kubernetes.show_service"](name, namespace, **kwargs)

    if service is None:
        ret["result"] = True if not __opts__["test"] else None
        ret["comment"] = "The service does not exist"
        return ret

    if __opts__["test"]:
        ret["comment"] = "The service is going to be deleted"
        ret["result"] = None
        return ret

    res = __salt__["kubernetes.delete_service"](name, namespace, **kwargs)
    if res["code"] == 200:
        ret["result"] = True
        ret["changes"] = {"kubernetes.service": {"new": "absent", "old": "present"}}
        ret["comment"] = res["message"]
    else:
        ret["comment"] = f"Something went wrong, response: {res}"

    return ret


def service_account_present(
    name,
    namespace="default",
    metadata=None,
    automount_service_account_token=None,
    image_pull_secrets=None,
    secrets=None,
    rebuild=False,
    **kwargs
):
    """
    Ensures that the named serviceaccount is present inside of the specified namespace
    with the given metadata and spec.
    If the deployment exists it will be replaced.

    name
        The name of the service.

    namespace
        The namespace holding the service account. The 'default' one is going
        to be used unless a different one is specified.

    metadata
        The metadata of the serviceaccount object.

    automount_service_account_token
        Indicate whether pods running as this service account should have an
        API token automatically mounted.

    image_pull_secrets
        List of secrets in the same namespace to use for pulling any images in
        pods that reference this ServiceAccount.

    secrets
        List of secrets in the same namespace that pods running using this
        ServiceAccount are allowed to use.

    rebuild
        Delete and recreate the resource if a non-fatal error is encountered
    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    if metadata is None:
        metadata = {}

    service_account = __salt__["kubernetes.show_service_account"](name, namespace, **kwargs)

    if service_account is None:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The serviceaccount is going to be created"
            return ret
        res = __salt__["kubernetes.create_service_account"](
            name=name,
            metadata=metadata,
            saltenv=__env__,
            namespace=namespace,
            automount_service_account_token=automount_service_account_token,
            image_pull_secrets=image_pull_secrets,
            secrets=secrets,
            rebuild=rebuild,
            **kwargs
        )
        ret["changes"][f"{namespace}.{name}"] = {"old": {}, "new": res}
    else:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The serviceaccount is going to be replaced"
            return ret

        # TODO: improve checks  # pylint: disable=fixme
        log.info("Forcing the recreation of the serviceaccount")
        ret["comment"] = "The serviceaccount is already present. Forcing recreation"
        res = __salt__["kubernetes.replace_service_account"](
            name=name,
            metadata=metadata,
            saltenv=__env__,
            namespace=namespace,
            automount_service_account_token=automount_service_account_token,
            image_pull_secrets=image_pull_secrets,
            secrets=secrets,
            old_service_account=service_account,
            rebuild=rebuild,
            **kwargs
        )

    ret["changes"] = {"metadata": metadata,
            "automount_service_account_token": automount_service_account_token,
            "image_pull_secrets": image_pull_secrets,
            "secrets": secrets,
    }
    ret["result"] = True
    return ret


def service_account_absent(name, namespace="default", **kwargs):
    """
    Ensures that the named serviceaccount is absent from the given namespace.

    name
        The name of the serviceaccount

    namespace
        The namespace holding the service account. The 'default' one is going
        to be used unless a different one is specified.
    """

    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    service_account = __salt__["kubernetes.show_service_account"](name, namespace, **kwargs)

    if service_account is None:
        ret["result"] = True if not __opts__["test"] else None
        ret["comment"] = "The serviceaccount does not exist"
        return ret

    if __opts__["test"]:
        ret["result"] = None
        ret["comment"] = "The serviceaccount is going to be deleted"
        return ret

    res = __salt__["kubernetes.delete_service_account"](name, namespace, **kwargs)
    if res["code"] == 200:
        ret["result"] = True
        ret["changes"] = {"kubernetes.serviceaccount": {"new": "absent", "old": "present"}}
        ret["comment"] = res["message"]
    else:
        ret["comment"] = f"Something went wrong, response: {res}"

    return ret


def namespace_absent(name, **kwargs):
    """
    Ensures that the named namespace is absent.

    name
        The name of the namespace
    """

    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    namespace = __salt__["kubernetes.show_namespace"](name, **kwargs)

    if namespace is None:
        ret["result"] = True if not __opts__["test"] else None
        ret["comment"] = "The namespace does not exist"
        return ret

    if __opts__["test"]:
        ret["comment"] = "The namespace is going to be deleted"
        ret["result"] = None
        return ret

    res = __salt__["kubernetes.delete_namespace"](name, **kwargs)
    if (
        res["code"] == 200
        or (isinstance(res["status"], str) and "Terminating" in res["status"])
        or (isinstance(res["status"], dict) and res["status"]["phase"] == "Terminating")
    ):
        ret["result"] = True
        ret["changes"] = {"kubernetes.namespace": {"new": "absent", "old": "present"}}
        if res["message"]:
            ret["comment"] = res["message"]
        else:
            ret["comment"] = "Terminating"
    else:
        ret["comment"] = f"Something went wrong, response: {res}"

    return ret


def namespace_present(name, **kwargs):
    """
    Ensures that the named namespace is present.

    name
        The name of the namespace.

    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    namespace = __salt__["kubernetes.show_namespace"](name, **kwargs)

    if namespace is None:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The namespace is going to be created"
            return ret

        res = __salt__["kubernetes.create_namespace"](name, **kwargs)
        ret["result"] = True
        ret["changes"]["namespace"] = {"old": {}, "new": res}
    else:
        ret["result"] = True if not __opts__["test"] else None
        ret["comment"] = "The namespace already exists"

    return ret


def persistentvolume_absent(name, **kwargs):
    """
    Ensures that the named PersitentVolume is absent.

    name
        The name of the PersistentVolume

    """

    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    pv = __salt__["kubernetes.show_persistentvolume"](name, **kwargs)

    if pv is None:
        ret["result"] = True if not __opts__["test"] else None
        ret["comment"] = "The PersistentVolume does not exist"
        return ret

    if __opts__["test"]:
        ret["result"] = None
        ret["comment"] = "The PersistentVolume is going to be deleted"
        return ret

    __salt__["kubernetes.delete_persistentvolume"](name, **kwargs)

    # As for kubernetes 1.6.4 doesn't set a code when deleting a persistentvolume
    # The kubernetes module will raise an exception if the kubernetes
    # server will return an error
    ret["result"] = True
    ret["changes"] = {"kubernetes.persistentvolume": {"new": "absent", "old": "present"}}
    ret["comment"] = "PersistentVolume deleted"
    return ret


def persistentvolume_present(
    name,
    metadata=None,
    spec=None,
    status=None,
    **kwargs
):
    """
    Ensures that the named PersistentVolume is present.

    name
        The name of the PersistentVolume.

    metadata
        The metadata of the PersistentVolume object.

    spec
        The spec of the PersistentVolume object.

    status
        The status of the PersistentVolume object.

    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    if metadata is None:
        metadata = {}

    pv = __salt__["kubernetes.show_persistentvolume"](name, **kwargs)

    if pv is None:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The PersistentVolume is going to be created"
            return ret
        res = __salt__["kubernetes.create_persistentvolume"](
            name=name,
            metadata=metadata,
            spec=spec,
            status=status,
            saltenv=__env__,
            **kwargs
        )
        ret["changes"][f"{name}"] = {"old": {}, "new": res}
    else:
        ret["comment"] = "The PersistentVolume is already present"
        if __opts__["test"]:
            ret["result"] = None
            return ret

    ret["changes"] = {"metadata": metadata, "spec": spec}
    ret["result"] = True
    return ret

def persistentvolumeclaim_absent(name, namespace="default", **kwargs):
    """
    Ensures that the named PersistentVolumeClaim is absent from the given namespace.

    name
        The name of the PersistentVolumeClaim

    namespace
        The name of the namespace
    """

    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    pvc = __salt__["kubernetes.show_persistentvolumeclaim"](name, namespace, **kwargs)

    if pvc is None:
        ret["result"] = True if not __opts__["test"] else None
        ret["comment"] = "The PersistentVolumeClaim does not exist"
        return ret

    if __opts__["test"]:
        ret["result"] = None
        ret["comment"] = "The PersistentVolumeClaim is going to be deleted"
        return ret

    __salt__["kubernetes.delete_persistentvolumeclaim"](name, namespace, **kwargs)

    # As for kubernetes 1.6.4 doesn't set a code when deleting a secret
    # The kubernetes module will raise an exception if the kubernetes
    # server will return an error
    ret["result"] = True
    ret["changes"] = {"kubernetes.persistentvolumeclaim": {"new": "absent", "old": "present"}}
    ret["comment"] = "PersistentVolumeClaim deleted"
    return ret

def persistentvolumeclaim_present(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    status=None,
    **kwargs
):
    """
    Ensures that the named PersistentVolumeClaim is present inside of
    the specified namespace with the given metadata and spec.

    name
        The name of the PersistentVolumeClaim.

    namespace
        The namespace holding the PersistentVolumeClaim. The 'default' one is
        going to be used unless a different one is specified.

    metadata
        The metadata of the PersistentVolumeClaim object.

    spec
        The spec of the PersistentVolumeClaim object.

    status
        The status of the PersistentVolumeClaim object.

    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    if metadata is None:
        metadata = {}

    if spec is None:
        spec = {}

    pvc = __salt__["kubernetes.show_persistentvolumeclaim"](name, namespace, **kwargs)

    if pvc is None:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The PersistentVolumeClaim is going to be created"
            return ret
        res = __salt__["kubernetes.create_persistentvolumeclaim"](
            name=name,
            namespace=namespace,
            metadata=metadata,
            spec=spec,
            status=status,
            saltenv=__env__,
            **kwargs
        )
        ret["changes"]["{namespace}.{name}"] = {"old": {}, "new": res}
    else:
        ret["comment"] = "The PersistentVolumeClaim is already present"
        if __opts__["test"]:
            ret["result"] = None
            return ret

    ret["changes"] = {"metadata": metadata, "spec": spec}
    ret["result"] = True
    return ret


def role_absent(name, namespace, **kwargs):
    """
    Ensures that the named role is absent.

    name
        The name of the role

    namespace
        The namespace holding the role. The 'default' one is going to be used
        unless a different one is specified.

    """

    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    role = __salt__["kubernetes.show_role"](name, namespace, **kwargs)

    if role is None:
        ret["result"] = True if not __opts__["test"] else None
        ret["comment"] = "The role does not exist"
        return ret

    if __opts__["test"]:
        ret["result"] = None
        ret["comment"] = "The role is going to be deleted"
        return ret

    res = __salt__["kubernetes.delete_role"](name, namespace, **kwargs)
    if res["code"] == 200:
        ret["result"] = True
        ret["changes"] = {"kubernetes.role": {"new": "absent", "old": "present"}}
        ret["comment"] = res["message"]
    else:
        ret["comment"] = f"Something went wrong, response: {res}"

    return ret


def role_present(
    name,
    namespace="default",
    metadata=None,
    rules=None,
    **kwargs
):
    """
    Ensures that the named role is present.
    If the role exists it will be replaced.

    name
        The name of the role.

    namespace
        The namespace holding the role. The 'default' one is going to be used
        unless a different one is specified.

    metadata
        The metadata of the role object.

    rules
        The rules of the role object.

    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    if metadata is None:
        metadata = {}

    # if rules is None:
    #    rules = {}

    role = __salt__["kubernetes.show_role"](name, namespace, **kwargs)

    if role is None:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The role is going to be created"
            return ret
        res = __salt__["kubernetes.create_role"](
            name=name,
            namespace=namespace,
            metadata=metadata,
            rules=rules,
            saltenv=__env__,
            **kwargs
        )
        ret["changes"][f"{name}"] = {"old": {}, "new": res}
    else:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The Role is going to be replaced"
            return ret

        # TODO: improve checks  # pylint: disable=fixme
        log.info("Forcing the recreation of the role")
        ret["comment"] = "The role is already present. Forcing recreation"
        res = __salt__["kubernetes.replace_role"](
            name=name,
            namespace=namespace,
            metadata=metadata,
            rules=rules,
            old_role=role,
            saltenv=__env__,
            **kwargs
        )

    ret["changes"] = {"metadata": metadata, "rules": rules}
    ret["result"] = True
    return ret


def cluster_role_absent(name, **kwargs):
    """
    Ensures that the named ClusterRole is absent.

    name
        The name of the role
    """

    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    role = __salt__["kubernetes.show_cluster_role"](name, **kwargs)

    if role is None:
        ret["result"] = True if not __opts__["test"] else None
        ret["comment"] = "The ClusterRole does not exist"
        return ret

    if __opts__["test"]:
        ret["result"] = None
        ret["comment"] = "The ClusterRole is going to be deleted"
        return ret

    res = __salt__["kubernetes.delete_cluster_role"](name, **kwargs)
    if res["code"] == 200:
        ret["result"] = True
        ret["changes"] = {"kubernetes.cluster_role": {"new": "absent", "old": "present"}}
        ret["comment"] = res["message"]
    else:
        ret["comment"] = f"Something went wrong, response: {res}"

    return ret


def cluster_role_present(
    name,
    metadata=None,
    rules=None,
    **kwargs
):
    """
    Ensures that the named ClusterRole is present.
    If the role exists it will be replaced.

    name
        The name of the ClusterRole.

    metadata
        The metadata of the ClusterRole object.

    rules
        The rules of the ClusterRole object.

    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    # if metadata is None:
    #    metadata = {}

    # if rules is None:
    #    rules = {}

    role = __salt__["kubernetes.show_cluster_role"](name, **kwargs)

    if role is None:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The ClusterRole is going to be created"
            return ret
        res = __salt__["kubernetes.create_cluster_role"](
            name=name,
            metadata=metadata,
            rules=rules,
            saltenv=__env__,
            **kwargs
        )
        ret["changes"][f"{name}"] = {"old": {}, "new": res}
    else:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The ClusterRole is going to be replaced"
            return ret

        # TODO: improve checks  # pylint: disable=fixme
        log.info("Forcing the recreation of the ClusterRole")
        ret["comment"] = "The ClusterRole is already present. Forcing recreation"
        res = __salt__["kubernetes.replace_cluster_role"](
            name=name,
            metadata=metadata,
            rules=rules,
            old_role=role,
            saltenv=__env__,
            **kwargs
        )

    ret["changes"] = {"metadata": metadata, "rules": rules}
    ret["result"] = True
    return ret


def role_binding_absent(name, namespace="default", **kwargs):
    """
    Ensures that the named RoleBinding is absent.

    name
        The name of the RoleBinding

    namespace
        The namespace holding the role. The 'default' one is going to be used
        unless a different one is specified.

    """

    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    role = __salt__["kubernetes.show_role_binding"](name, namespace, **kwargs)

    if role is None:
        ret["result"] = True if not __opts__["test"] else None
        ret["comment"] = "The role binding does not exist"
        return ret

    if __opts__["test"]:
        ret["result"] = None
        ret["comment"] = "The role binding is going to be deleted"
        return ret

    res = __salt__["kubernetes.delete_role_binding"](name, namespace, **kwargs)
    if res["code"] == 200:
        ret["result"] = True
        ret["changes"] = {"kubernetes.role_binding": {"new": "absent", "old": "present"}}
        ret["comment"] = res["message"]
    else:
        ret["comment"] = f"Something went wrong, response: {res}"

    return ret


def role_binding_present(
    name,
    namespace="default",
    metadata=None,
    roleRef=None,
    subjects=None,
    **kwargs
):
    """
    Ensures that the named RoleBinding is present.
    If the RoleBinding exists it will be replaced.

    name
        The name of the RoleBinding.

    namespace
        The namespace holding the RoleBinding. The 'default' one is going to
        be used unless a different one is specified.

    metadata
        The metadata of the RoleBinding object.

    roleRef
        The roleRef of the RoleBinding object.

    subjects
        The subjects of the RoleBinding object.

    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    if metadata is None:
        metadata = {}

    # if rules is None:
    #    rules = {}

    role_binding = __salt__["kubernetes.show_role_binding"](name, namespace, **kwargs)

    if role_binding is None:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The RoleBinding is going to be created"
            return ret
        res = __salt__["kubernetes.create_role_binding"](
            name=name,
            namespace=namespace,
            metadata=metadata,
            role_ref=roleRef,
            subjects=subjects,
            saltenv=__env__,
            **kwargs
        )
        ret["changes"][f"{name}"] = {"old": {}, "new": res}
    else:
        if __opts__["test"]:
            ret["comment"] = "The RoleBinding is going to be replaced"
            ret["result"] = None
            return ret

        # TODO: improve checks  # pylint: disable=fixme
        log.info("Forcing the recreation of the RoleBinding")
        ret["comment"] = "The RoleBinding is already present. Forcing recreation"
        res = __salt__["kubernetes.replace_role_binding"](
            name=name,
            namespace=namespace,
            metadata=metadata,
            role_ref=roleRef,
            subjects=subjects,
            old_role_binding=role_binding,
            saltenv=__env__,
            **kwargs
        )

    ret["changes"] = {"metadata": metadata, "roleRef": roleRef, "subjects": subjects}
    ret["result"] = True
    return ret


def cluster_role_binding_absent(name, **kwargs):
    """
    Ensures that the named ClusterRoleBinding is absent.

    name
        The name of the ClusterRoleBinding

    """

    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    role = __salt__["kubernetes.show_cluster_role_binding"](name, **kwargs)

    if role is None:
        ret["result"] = True if not __opts__["test"] else None
        ret["comment"] = "The CluterRole binding does not exist"
        return ret

    if __opts__["test"]:
        ret["result"] = None
        ret["comment"] = "The ClusterRole binding is going to be deleted"
        return ret

    res = __salt__["kubernetes.delete_cluster_role_binding"](name, **kwargs)
    if res["code"] == 200:
        ret["result"] = True
        ret["changes"] = {"kubernetes.cluster_role_binding": {"new": "absent", "old": "present"}}
        ret["comment"] = res["message"]
    else:
        ret["comment"] = f"Something went wrong, response: {res}"

    return ret


def cluster_role_binding_present(
    name,
    metadata=None,
    roleRef=None,
    subjects=None,
    **kwargs
):
    """
    Ensures that the named ClusterRoleBinding is present.
    If the ClusterRoleBinding exists it will be replaced.

    name
        The name of the ClusterRoleBinding.

    metadata
        The metadata of the RoleBinding object.

    roleRef
        The roleRef of the RoleBinding object.

    subjects
        The subjects of the RoleBinding object.

    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    #if metadata is None:
    #    metadata = {}

    # if rules is None:
    #    rules = {}

    role_binding = __salt__["kubernetes.show_cluster_role_binding"](name, **kwargs)

    if role_binding is None:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The ClusterRoleBinding is going to be created"
            return ret
        res = __salt__["kubernetes.create_cluster_role_binding"](
            name=name,
            metadata=metadata,
            role_ref=roleRef,
            subjects=subjects,
            saltenv=__env__,
            **kwargs
        )
        ret["changes"][f"{name}"] = {"old": {}, "new": res}
    else:
        if __opts__["test"]:
            ret["comment"] = "The ClusterRoleBinding is going to be replaced"
            ret["result"] = None
            return ret

        # TODO: improve checks  # pylint: disable=fixme
        log.info("Forcing the recreation of the ClusterRoleBinding")
        ret["comment"] = "The ClusterRoleBinding is already present. Forcing recreation"
        res = __salt__["kubernetes.replace_cluster_role_binding"](
            name=name,
            metadata=metadata,
            role_ref=roleRef,
            subjects=subjects,
            old_role_binding=role_binding,
            saltenv=__env__,
            **kwargs
        )

    ret["changes"] = {"metadata": metadata, "roleRef": roleRef, "subjects": subjects}
    ret["result"] = True
    return ret


def secret_absent(name, namespace="default", **kwargs):
    """
    Ensures that the named secret is absent from the given namespace.

    name
        The name of the secret

    namespace
        The name of the namespace
    """

    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    secret = __salt__["kubernetes.show_secret"](name, namespace, **kwargs)

    if secret is None:
        ret["result"] = True if not __opts__["test"] else None
        ret["comment"] = "The secret does not exist"
        return ret

    if __opts__["test"]:
        ret["comment"] = "The secret is going to be deleted"
        ret["result"] = None
        return ret

    __salt__["kubernetes.delete_secret"](name, namespace, **kwargs)

    # As for kubernetes 1.6.4 doesn't set a code when deleting a secret
    # The kubernetes module will raise an exception if the kubernetes
    # server will return an error
    ret["result"] = True
    ret["changes"] = {"kubernetes.secret": {"new": "absent", "old": "present"}}
    ret["comment"] = "Secret deleted"
    return ret


def secret_present(
    name,
    namespace="default",
    data=None,
    stringData=None,
    metadata=None,
    source=None,
    template=None,
    context=None,
    type="Opaque",
    rebuild=False,
    **kwargs
):
    """
    Ensures that the named secret is present inside of the specified namespace
    with the given data.
    If the secret exists it will be replaced.

    name
        The name of the secret.

    namespace
        The namespace holding the secret. The 'default' one is going to be
        used unless a different one is specified.

    data
        The dictionary holding the secrets.

    stringData
        The dictionary holding the stringData secrets.

    metadata
        The dictionary of metadata values (omitting namespace and name)

    source
        A file containing the data of the secret in plain format.

    template
        Template engine to be used to render the source file.

    context
        Context variables passed to the template

    type
        The type of secret. Default is Opaque

    rebuild
        Delete and recreate the resource if a non-fatal error is encountered
    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    if data and source:
        return _error(ret, "'source' cannot be used in combination with 'data'")

    secret = __salt__["kubernetes.show_secret"](name, namespace, **kwargs)

    if secret is None:
        if data is None:
            data = {}

        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The secret is going to be created"
            return ret
        res = __salt__["kubernetes.create_secret"](
            name=name,
            namespace=namespace,
            data=data,
            stringData=stringData,
            metadata=metadata,
            source=source,
            template=template,
            context=context,
            type=type,
            saltenv=__env__,
            **kwargs
        )
        ret["changes"][f"{namespace}.{name}"] = {"old": {}, "new": res}
    else:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The secret is going to be replaced"
            return ret

        # TODO: improve checks  # pylint: disable=fixme
        log.info("Forcing the recreation of the service")
        ret["comment"] = "The secret is already present. Forcing recreation"
        res = __salt__["kubernetes.replace_secret"](
            name=name,
            namespace=namespace,
            data=data,
            stringData=stringData,
            metadata=metadata,
            source=source,
            template=template,
            context=context,
            type=type,
            rebuild=rebuild,
            saltenv=__env__,
            **kwargs,
        )
    # Omit values from the return. They are unencrypted
    # and can contain sensitive data.
    try:
        clean_data = list(res["data"])
    # TypeError: 'NoneType' object is not iterable
    except (TypeError) as exc:
        clean_data = []

    ret["changes"] = {
        # Omit values from the return. They are unencrypted
        # and can contain sensitive data.
        "data": list(res["data"])
    }
    ret["result"] = True

    return ret


def configmap_absent(name, namespace="default", **kwargs):
    """
    Ensures that the named configmap is absent from the given namespace.

    name
        The name of the configmap

    namespace
        The namespace holding the configmap. The 'default' one is going to be
        used unless a different one is specified.
    """

    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    configmap = __salt__["kubernetes.show_configmap"](name, namespace, **kwargs)

    if configmap is None:
        ret["result"] = True if not __opts__["test"] else None
        ret["comment"] = "The configmap does not exist"
        return ret

    if __opts__["test"]:
        ret["comment"] = "The configmap is going to be deleted"
        ret["result"] = None
        return ret

    __salt__["kubernetes.delete_configmap"](name, namespace, **kwargs)
    # As for kubernetes 1.6.4 doesn't set a code when deleting a configmap
    # The kubernetes module will raise an exception if the kubernetes
    # server will return an error
    ret["result"] = True
    ret["changes"] = {"kubernetes.configmap": {"new": "absent", "old": "present"}}
    ret["comment"] = "ConfigMap deleted"

    return ret


def configmap_present(
    name,
    namespace="default",
    data=None,
    metadata=None,
    source=None,
    template=None,
    context=None,
    rebuild=False,
    **kwargs
):
    """
    Ensures that the named configmap is present inside of the specified namespace
    with the given data.
    If the configmap exists it will be replaced.

    name
        The name of the configmap.

    namespace
        The namespace holding the configmap. The 'default' one is going to be
        used unless a different one is specified.

    data
        The dictionary holding the configmaps.

    metadata
        The dictionary of metadata values (omitting namespace and name)

    source
        A file containing the data of the configmap in plain format.

    template
        Template engine to be used to render the source file.

    context
        Context variables passed to the template

    rebuild
        Delete and recreate the resource if a non-fatal error is encountered
    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    if data and source:
        return _error(ret, "'source' cannot be used in combination with 'data'")
    elif data is None:
        data = {}

    configmap = __salt__["kubernetes.show_configmap"](name, namespace, **kwargs)

    if configmap is None:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The configmap is going to be created"
            return ret
        res = __salt__["kubernetes.create_configmap"](
            name=name,
            namespace=namespace,
            data=data,
            metadata=metadata,
            source=source,
            template=template,
            context=context,
            saltenv=__env__,
            **kwargs,
        )
        ret["changes"][f"{namespace}.{name}"] = {"old": {}, "new": res}
    else:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The configmap is going to be replaced"
            return ret

        # TODO: improve checks  # pylint: disable=fixme
        log.info("Forcing the recreation of the service")
        ret["comment"] = "The configmap is already present. Forcing recreation"
        res = __salt__["kubernetes.replace_configmap"](
            name=name,
            namespace=namespace,
            data=data,
            metadata=metadata,
            source=source,
            template=template,
            context=context,
            rebuild=rebuild,
            saltenv=__env__,
            **kwargs
        )

    ret["changes"] = {"data": res["data"]}
    ret["result"] = True
    return ret

def namespaced_custom_obj_absent(
    name,
    namespace="default",
    apiVersion="v1",
    kind=None,
    **kwargs
):
    """
    Ensures that the namespaced custom object is absent inside of the
    specified namespace with the given data.

    name
        The name of the object.

    namespace
        The namespace holding the object. The 'default' one is going to be
        used unless a different one is specified.

    apiVersion
        The apiVersion to specify for the resource.

    kind
        The kind of the custom resource.

    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    res_def = __salt__["kubernetes.get_resource_def"](apiVersion=apiVersion, kind=kind)

    if res_def is None:
        ret["result"] = False
        ret["comment"] = (f"The resource definition '{apiVersion}:{kind}'"
                          f" cannot be found"
                         )
        return ret

    obj = __salt__["kubernetes.show_namespaced_custom_obj"](
        name, apiVersion, kind, namespace, **kwargs
    )

    if obj is None:
        ret["result"] = True if not __opts__["test"] else None
        ret["comment"] = "The object does not exist"
        return ret

    if __opts__["test"]:
        ret["result"] = None
        ret["comment"] = "The object is going to be deleted"
        return ret

    res = __salt__["kubernetes.delete_namespaced_custom_obj"](name, namespace, apiVersion, kind, **kwargs)

    if res["code"] == 200:
        ret["result"] = True
        ret["changes"] = {"kubernetes.namespaced_custom_obj": {"new": "absent", "old": "present"}}
        ret["comment"] = res["message"]
    else:
        ret["comment"] = f"Something went wrong, response: {res}"

    return ret


def namespaced_custom_obj_present(
    name,
    namespace="default",
    apiVersion="v1",
    kind=None,
    metadata=None,
    spec=None,
    status=None,
    source=None,
    template=None,
    context=None,
    rebuild=False,
    **kwargs
):
    """
    Ensures that the namespaced custom object is present inside of the
    specified namespace with the given data.
    If the custom object exists it will be replaced.

    name
        The name of the object.

    namespace
        The namespace holding the object. The 'default' one is going to be
        used unless a different one is specified.

    apiVersion
        The apiVersion to specify for the resource.

    kind
        The kind of the custom resource.

    metadata
        The dictionary of metadata values (omitting namespace and name).

    spec
        The spec of the custom object.

    status
        The status of the custom object.

    source
        A file containing the data of the object in plain format.

    template
        Template engine to be used to render the source file.

    context
        Context variables passed to the template

    rebuild
        Delete and recreate the resource if a non-fatal error is encountered
    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    res_def = __salt__["kubernetes.get_resource_def"](apiVersion=apiVersion, kind=kind)

    if res_def is None:
        ret["result"] = False
        ret["comment"] = (f"The resource definition '{apiVersion}:{kind}'"
                          f" cannot be found"
                         )
        return ret

    obj = __salt__["kubernetes.show_namespaced_custom_obj"](
        name, apiVersion, kind, namespace, **kwargs
    )

    if obj is None:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The object is going to be created"
            return ret
        res = __salt__["kubernetes.create_namespaced_custom_obj"](
            name=name,
            namespace=namespace,
            apiVersion=apiVersion,
            kind=kind,
            metadata=metadata,
            spec=spec,
            status=status,
            source=source,
            template=template,
            context=context,
            saltenv=__env__,
            **kwargs
        )
        ret["changes"][f"{namespace}.{name}"] = {"old": {}, "new": res}
    else:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The custom object is going to be replaced"
            return ret

        # TODO: improve checks  # pylint: disable=fixme
        log.info("Forcing the recreation of the custom object")
        ret["comment"] = "The custom object is already present. Forcing recreation"
        res = __salt__["kubernetes.replace_namespaced_custom_obj"](
            name=name,
            namespace=namespace,
            apiVersion=apiVersion,
            kind=kind,
            metadata=metadata,
            spec=spec,
            status=status,
            source=source,
            template=template,
            context=context,
            saltenv=__env__,
            **kwargs
        )

    ret["changes"] = {"data": res["data"]}
    ret["result"] = True
    return ret

def custom_obj_absent(
    name,
    apiVersion="v1",
    kind=None,
    **kwargs
):
    """
    Ensures that the cluster scope custom object is absent inside of the
    specified namespace with the given data.

    name
        The name of the object.

    apiVersion
        The apiVersion to specify for the resource.

    kind
        The kind of the custom resource.

    spec
        The spec of the custom object.

    status
        The status of the custom object.

    source
        A file containing the data of the object in plain format.

    template
        Template engine to be used to render the source file.

    context
        Context variables passed to the template

    rebuild
        Delete and recreate the resource if a non-fatal error is encountered
    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    res_def = __salt__["kubernetes.get_resource_def"](apiVersion=apiVersion, kind=kind)

    if res_def is None:
        ret["result"] = False
        ret["comment"] = (f"The resource definition '{apiVersion}:{kind}'"
                          f" cannot be found"
                         )
        return ret

    obj = __salt__["kubernetes.show_custom_obj"](
        name, apiVersion, kind, **kwargs
    )

    if obj is None:
        ret["result"] = True if not __opts__["test"] else None
        ret["comment"] = "The object does not exist"
        return ret

    if __opts__["test"]:
        ret["comment"] = "The object is going to be deleted"
        ret["result"] = None
        return ret

    __salt__["kubernetes.delete_custom_obj"](name,
                                             apiVersion=apiVersion,
                                             kind=kind, **kwargs)
    ret["result"] = True
    ret["changes"] = {"kubernetes.custom_obj": {"new": "absent", "old": "present"}}
    ret["comment"] = f"{kind} {name} deleted"

    return ret


def custom_obj_present(
    name,
    apiVersion="v1",
    kind=None,
    metadata=None,
    spec=None,
    status=None,
    source=None,
    template=None,
    context=None,
    rebuild=False,
    **kwargs
):
    """
    Ensures that the custom object is present inside of the
    specified namespace with the given data.
    If the custom object exists it will be replaced.

    name
        The name of the object.

    apiVersion
        The apiVersion to specify for the resource.

    kind
        The kind of the custom resource.

    metadata
        The dictionary of metadata values (omitting namespace and name).

    spec
        The spec of the custom object.

    status
        The status of the custom object.

    source
        A file containing the data of the object in plain format.

    template
        Template engine to be used to render the source file.

    context
        Context variables passed to the template

    rebuild
        Delete and recreate the resource if a non-fatal error is encountered
    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    res_def = __salt__["kubernetes.get_resource_def"](apiVersion=apiVersion, kind=kind)

    if res_def is None:
        ret["result"] = False
        ret["comment"] = (f"The resource definition '{apiVersion}:{kind}'"
                          f" cannot be found"
                         )
        return ret

    obj = __salt__["kubernetes.show_custom_obj"](
        name, apiVersion, kind, **kwargs
    )

    if obj is None:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The object is going to be created"
            return ret
        res = __salt__["kubernetes.create_custom_obj"](
            name=name,
            apiVersion=apiVersion,
            kind=kind,
            metadata=metadata,
            spec=spec,
            status=status,
            source=source,
            template=template,
            context=context,
            saltenv=__env__,
            **kwargs
        )
        ret["changes"][f"{kind}.{name}"] = {"old": {}, "new": res}
    else:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The custom object is going to be replaced"
            return ret

        # TODO: improve checks  # pylint: disable=fixme
        log.info("Forcing the recreation of the custom object")
        ret["comment"] = "The custom object is already present. Forcing recreation"
        res = __salt__["kubernetes.replace_custom_obj"](
            name=name,
            apiVersion=apiVersion,
            kind=kind,
            metadata=metadata,
            spec=spec,
            status=status,
            source=source,
            template=template,
            context=context,
            saltenv=__env__,
            **kwargs
        )

    ret["changes"] = {"data": res["data"]}
    ret["result"] = True
    return ret


def pod_absent(name, namespace="default", **kwargs):
    """
    Ensures that the named pod is absent from the given namespace.

    name
        The name of the pod

    namespace
        The name of the namespace
    """

    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    pod = __salt__["kubernetes.show_pod"](name, namespace, **kwargs)

    if pod is None:
        ret["result"] = True if not __opts__["test"] else None
        ret["comment"] = "The pod does not exist"
        return ret

    if __opts__["test"]:
        ret["comment"] = "The pod is going to be deleted"
        ret["result"] = None
        return ret

    res = __salt__["kubernetes.delete_pod"](name, namespace, **kwargs)
    if res["code"] == 200 or res["code"] is None:
        ret["result"] = True
        ret["changes"] = {"kubernetes.pod": {"new": "absent", "old": "present"}}
        if res["code"] is None:
            ret["comment"] = "In progress"
        else:
            ret["comment"] = res["message"]
    else:
        ret["comment"] = f"Something went wrong, response: {res}"

    return ret


def pod_present(
    name,
    namespace="default",
    metadata=None,
    spec=None,
    source="",
    template="",
    context=None,
    rebuild=False,
    **kwargs
):
    """
    Ensures that the named pod is present inside of the specified
    namespace with the given metadata and spec.
    If the pod exists it will be replaced.

    name
        The name of the pod.

    namespace
        The namespace holding the pod. The 'default' one is going to be
        used unless a different one is specified.

    metadata
        The metadata of the pod object.

    spec
        The spec of the pod object.

    source
        A file containing the definition of the pod (metadata and
        spec) in the official kubernetes format.

    template
        Template engine to be used to render the source file.

    context
        Context variables passed to the template

    rebuild
        Delete and recreate the resource if a non-fatal error is encountered
    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    if (metadata or spec) and source:
        return _error(ret, "'source' cannot be used in combination with 'metadata' or 'spec'")

    if metadata is None:
        metadata = {}

    if spec is None:
        spec = {}

    pod = __salt__["kubernetes.show_pod"](name, namespace, **kwargs)

    if pod is None:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The pod is going to be created"
            return ret
        res = __salt__["kubernetes.create_pod"](
            name=name,
            namespace=namespace,
            metadata=metadata,
            spec=spec,
            source=source,
            template=template,
            context=context,
            saltenv=__env__,
            **kwargs,
        )
        ret["changes"][f"{namespace}.{name}"] = {"old": {}, "new": res}
    else:
        if __opts__["test"]:
            ret["result"] = None
            return ret

        # TODO: fix replace_namespaced_pod validation issues
        ret["comment"] = (
            "salt is currently unable to replace a pod without "
            "deleting it. Please perform the removal of the pod requiring "
            "the 'pod_absent' state if this is the desired behaviour."
        )
        ret["result"] = False
        return ret

    ret["changes"] = {"metadata": metadata, "spec": spec}
    ret["result"] = True
    return ret


def node_label_absent(name, node, **kwargs):
    """
    Ensures that the named label is absent from the node.

    name
        The name of the label

    node
        The name of the node
    """

    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    labels = __salt__["kubernetes.node_labels"](node, **kwargs)

    if name not in labels:
        ret["result"] = True if not __opts__["test"] else None
        ret["comment"] = "The label does not exist"
        return ret

    if __opts__["test"]:
        ret["comment"] = "The label is going to be deleted"
        ret["result"] = None
        return ret

    __salt__["kubernetes.node_remove_label"](node_name=node, label_name=name, **kwargs)

    ret["result"] = True
    ret["changes"] = {"kubernetes.node_label": {"new": "absent", "old": "present"}}
    ret["comment"] = "Label removed from node"

    return ret


def node_label_folder_absent(name, node, **kwargs):
    """
    Ensures the label folder doesn't exist on the specified node.

    name
        The name of label folder

    node
        The name of the node
    """

    ret = {"name": name, "changes": {}, "result": False, "comment": ""}
    labels = __salt__["kubernetes.node_labels"](node, **kwargs)

    folder = name.strip("/") + "/"
    labels_to_drop = []
    new_labels = []
    for label in labels:
        if label.startswith(folder):
            labels_to_drop.append(label)
        else:
            new_labels.append(label)

    if not labels_to_drop:
        ret["result"] = True if not __opts__["test"] else None
        ret["comment"] = "The label folder does not exist"
        return ret

    if __opts__["test"]:
        ret["comment"] = "The label folder is going to be deleted"
        ret["result"] = None
        return ret

    for label in labels_to_drop:
        __salt__["kubernetes.node_remove_label"](node_name=node, label_name=label, **kwargs)

    ret["result"] = True
    ret["changes"] = {
        "kubernetes.node_label_folder_absent": {"old": list(labels), "new": new_labels}
    }
    ret["comment"] = "Label folder removed from node"

    return ret


def node_label_present(name, node, value, **kwargs):
    """
    Ensures that the named label is set on the named node
    with the given value.
    If the label exists it will be replaced.

    name
        The name of the label.

    value
        Value of the label.

    node
        Node to change.
    """
    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    labels = __salt__["kubernetes.node_labels"](node, **kwargs)

    if name not in labels:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The label is going to be set"
            return ret
        __salt__["kubernetes.node_add_label"](
            label_name=name, label_value=value, node_name=node, **kwargs
        )
    elif labels[name] == value:
        ret["result"] = True
        ret["comment"] = "The label is already set and has the specified value"
        return ret
    else:
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "The label is going to be updated"
            return ret

        ret["comment"] = "The label is already set, changing the value"
        __salt__["kubernetes.node_add_label"](
            node_name=node, label_name=name, label_value=value, **kwargs
        )

    old_labels = copy.copy(labels)
    labels[name] = value

    ret["changes"][f"{node}.{name}"] = {"old": old_labels, "new": labels}
    ret["result"] = True

    return ret
