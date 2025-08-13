The changelog format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

This project uses [Semantic Versioning](https://semver.org/) - MAJOR.MINOR.PATCH

# Changelog

## 2.0.0 (2025-08-13)


### Breaking changes

- Dropped legacy connection setup. Either `kubeconfig` or `kubeconfig-data` and (always) `context` configuration is required now. This change affects backwards compatibility and may not work on very old versions of kubernetes.
- `kubernetes.create_configmap` with `source` parameter now expects to receive a properly formatted spec with the configmap data in the `data` key. Previously, the loaded data was used as the data directly.


### Added

- Added enhanced functionality including Jinja2 templating via `template_context` parameter, `wait` and `timeout` parameters for resource operations, `secret_type` and `metadata` parameters for secrets, and improved parameter validation across resource types. [#10](https://github.com/salt-extensions/saltext-kubernetes/issues/10)

## 1.1.0 (2025-01-14)


### Changed

- Updated `kubernetesmod` to work with newer versions of the Kubernetes Python client. [#1](https://github.com/salt-extensions/saltext-kubernetes/issues/1)


## 1.0.1 (2023-12-29)

Initial release of `saltext-kubernetes`. This release tracks the functionality in the core Salt code base at this point.
