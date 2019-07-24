# HTTPS Everywhere Core Library

[![Build Status](https://api.travis-ci.com/efforg/https-everywhere-lib-core.svg?branch=master)](https://travis-ci.com/efforg/https-everywhere-lib-core)
[![Latest Version](https://img.shields.io/crates/v/https-everywhere-lib-core.svg)](https://crates.io/crates/https-everywhere-lib-core)
[![Rust Documentation](https://img.shields.io/badge/api-rustdoc-blue.svg)](https://docs.rs/https-everywhere-lib-core)

## Features

This library includes various compilation features, all included by default.  To include only a subset of these features, be sure to specify `default_features = false, features = ["list_of_features_desired"]` in the downstream `Cargo.toml`.

Description of features follows.

### `add_rulesets`

Include the ability to add rulesets to a `RuleSets` instance via `RuleSets::add_all_from_json_string`.

### `potentially_applicable`

Include the ability to look up potentially applicable rulesets on a `RuleSets` instance via `RuleSets::potentially_applicable`.

### `updates`

Expose the structs necessary to update the rulesets dynamically via update channels.
