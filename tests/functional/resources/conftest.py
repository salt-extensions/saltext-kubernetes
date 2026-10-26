import contextlib
import copy

import pytest
import salt.loader
import salt.loader.context as loader_ctx

pytest.importorskip(
    "salt.utils.resources", reason="The resources subsystem requires Salt 3008.0 or newer"
)


@pytest.fixture(autouse=True)
def reset_loaders_state():
    """
    Shadow the parent conftest's autouse fixture of the same name so the
    classic factories loaders are not built for resource tests.
    """
    yield


@pytest.fixture(scope="module")
def res_type():
    """
    Resource type to test. Override per module.
    """
    return "kubernetes"


@pytest.fixture(scope="module")
def resource_decl():
    """
    The ``<res_type>`` entry of the resource pillar subtree.
    Override per test module.
    """
    return {}


@pytest.fixture(scope="module")
def res_opts(minion_opts, resource_decl, res_type):
    """
    Minion opts, including pillar definition for resources as specified
    by ``res_type`` and ``resource_decl``.
    """
    opts = copy.deepcopy(minion_opts)
    opts["pillar"] = {"resources": {res_type: resource_decl}}
    return opts


@pytest.fixture(scope="module")
def loader_context():
    return {}


@pytest.fixture(autouse=True)
def _fresh_loader_context(loader_context):
    """
    Reset the loader context per test.
    """
    try:
        yield
    finally:
        loader_context.clear()


@pytest.fixture(scope="module")
def utils_loader(res_opts):
    return salt.loader.utils(res_opts)


@pytest.fixture(scope="module")
def res_funcs(res_opts, utils_loader, loader_context):
    """
    Loader of resource connection modules.
    If the resource does not expose any override modules, only use this loader.
    """
    return salt.loader.resource(
        res_opts,
        utils=utils_loader,
        context=loader_context,
        loaded_base_name=f"{__name__}.resource",
    )


@pytest.fixture(scope="module")
def res_modules(res_opts, res_type, res_funcs, utils_loader, loader_context):
    """
    Loader of execution modules for the resource type specified in ``res_type``.
    Only relevant if the resource exposes override modules.
    """
    return salt.loader.resource_modules(
        res_opts,
        res_type,
        resource_funcs=res_funcs,
        utils=utils_loader,
        context=loader_context,
        loaded_base_name=f"{__name__}.resmods",
    )


@pytest.fixture
def for_resource(res_type):
    """
    Context manager setting ``__resource__`` for the duration of a call,
    mirroring what the minion's dispatch does.

    Usage:

    .. code-block:: py

        def test_foo_get(res_modules, for_resource):
            with for_resource("resource_id"):
                res = res_modules["foo.bar"]()
            # ...
    """

    @contextlib.contextmanager
    def _set(rid, rtype=res_type):
        token = loader_ctx.resource_ctxvar.set({"id": rid, "type": rtype})
        try:
            yield
        finally:
            loader_ctx.resource_ctxvar.reset(token)

    return _set
