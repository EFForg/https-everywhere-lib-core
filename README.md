# HTTPS Everywhere Core Library

[![CI](https://github.com/efforg/https-everywhere-lib-core/actions/workflows/ci.yml/badge.svg)](https://github.com/efforg/https-everywhere-lib-core/actions/workflows/ci.yml)
[![Latest Version](https://img.shields.io/crates/v/https-everywhere-lib-core.svg)](https://crates.io/crates/https-everywhere-lib-core)
[![Rust Documentation](https://img.shields.io/badge/api-rustdoc-blue.svg)](https://docs.rs/https-everywhere-lib-core)

## Features

This library includes various compilation features, all included by default.  To include only a subset of these features, be sure to specify `default_features = false, features = ["list_of_features_desired"]` in the downstream `Cargo.toml`.

Description of features follows.

### `add_rulesets`

Expose the high-level API for adding rulesets to a `RuleSets` instance via `RuleSets::add_all_from_json_string`.

### `get_simple_rules_ending_with`

Expose the high-level API for looking up simple rules on a `RuleSets` instance ending in a string via `RuleSets::get_simple_rules_ending_with`.

### `potentially_applicable`

Expose the high-level API for looking up potentially applicable rulesets on a `RuleSets` instance via `RuleSets::potentially_applicable`.

### `rewriter`

Expose the high-level API for rewriting URLs.

### `settings`

Expose the high-level API for retrieving and storing global settings.

### `updater`

Expose the high-level API for updating the rulesets dynamically via update channels.
