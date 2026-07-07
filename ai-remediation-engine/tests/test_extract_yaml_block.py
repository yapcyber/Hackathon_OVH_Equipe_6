import pytest

from job_runner.main import _extract_yaml_block


def test_extracts_first_valid_k8s_manifest_block():
    response = """Voici le correctif :
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
```
Explication : ...
"""
    assert "kind: Deployment" in _extract_yaml_block(response)


def test_tolerant_to_missing_language_tag():
    response = """```
apiVersion: v1
kind: Pod
metadata:
  name: demo
```"""
    assert "kind: Pod" in _extract_yaml_block(response)


def test_tolerant_to_uppercase_language_tag():
    response = """```YAML
apiVersion: v1
kind: Pod
metadata:
  name: demo
```"""
    assert "kind: Pod" in _extract_yaml_block(response)


def test_skips_non_manifest_block_and_picks_the_real_manifest():
    response = """```yaml
notes: pas un manifeste, pas de champ 'kind'
```
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
```"""
    assert "kind: Deployment" in _extract_yaml_block(response)


def test_raises_when_no_fenced_block_at_all():
    with pytest.raises(ValueError):
        _extract_yaml_block("Pas de bloc de code ici du tout.")


def test_raises_when_fenced_blocks_have_no_kind_field():
    response = """```yaml
just: some, unrelated, yaml
```"""
    with pytest.raises(ValueError):
        _extract_yaml_block(response)
