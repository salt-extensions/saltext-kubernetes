The changelog format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

This project uses [Semantic Versioning](https://semver.org/) - MAJOR.MINOR.PATCH

# Changelog

## 2.0.0 (2026-04-20)


### Breaking changes

- Dropped legacy connection setup. Either `kubeconfig` or `kubeconfig-data` and (always) `context` configuration is required now. This change affects backwards compatibility and may not work on very old versions of kubernetes.
- `kubernetes.create_configmap` with `source` parameter now expects to receive a properly formatted spec with the configmap data in the `data` key. Previously, the loaded data was used as the data directly.


### Changed

- API responses now return ``camelCase`` keys matching Kubernetes YAML manifests instead of ``snake_case``, and ``_present`` state functions use ``patch`` instead of delete-and-recreate (the ``replace`` parameter has been removed). [#16](https://github.com/salt-extensions/saltext-kubernetes/issues/16)


### Fixed

- Added Kubernetes patch functionality to the execution module for applying patch operations to cluster resources during runtime. Also fixed general idempotency issues in absent functions by checking resource existence before modifications. [#16](https://github.com/salt-extensions/saltext-kubernetes/issues/16)


### Added

- Added enhanced functionality including Jinja2 templating via `template_context` parameter, `wait` and `timeout` parameters for resource operations, `secret_type` and `metadata` parameters for secrets, and improved parameter validation across resource types. [#10](https://github.com/salt-extensions/saltext-kubernetes/issues/10)
- Added Kubernetes patch functionality to the execution module for applying patch operations to cluster resources during runtime. [#16](https://github.com/salt-extensions/saltext-kubernetes/issues/16)

## 1.1.0 (2025-01-14)


### Changed

- Updated `kubernetesmod` to work with newer versions of the Kubernetes Python client. [#1](https://github.com/salt-extensions/saltext-kubernetes/pull/1)


## 1.0.1 (2023-12-29)

Initial release of `saltext-kubernetes`. This release tracks the functionality in the core Salt code base at this point.
