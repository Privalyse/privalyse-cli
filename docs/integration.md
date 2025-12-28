# Integration Guide

Privalyse is designed to integrate seamlessly into your development workflow.

## GitHub Actions

Add Privalyse to your GitHub Actions pipeline to catch privacy issues on every push or pull request.

Create a file `.github/workflows/privacy.yml`:

```yaml
name: Privacy Scan
on: [push, pull_request]

jobs:
  privalyse:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Privalyse Scan
        uses: privalyse/privalyse-cli@v0.3.1
        with:
          # Optional: Specify root directory
          # root: './src'
          # Optional: Output format (markdown, json, html, sarif)
          format: 'sarif'
          out: 'results.sarif'

      # Optional: Upload results to GitHub Security tab
      - name: Upload SARIF file
        uses: github/codeql-action/upload-sarif@v2
        if: always() # Upload even if issues are found
        with:
          sarif_file: results.sarif
```

## GitLab CI

Add the following job to your `.gitlab-ci.yml`:

```yaml
privalyse_scan:
  image: python:3.11
  script:
    - pip install privalyse-cli
    - privalyse --out report.md
  artifacts:
    paths: [report.md]
    when: always
```

## Pre-Commit Hook

Prevent privacy leaks from being committed by adding Privalyse to your pre-commit configuration.

Add this to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: privalyse
        name: Privalyse Scan
        entry: privalyse
        language: system
        pass_filenames: false # Privalyse scans the whole project context
        always_run: true
```

## Bitbucket Pipelines

Add this to your `bitbucket-pipelines.yml`:

```yaml
pipelines:
  default:
    - step:
        name: Privalyse Privacy Scan
        image: python:3.11
        script:
          - pip install privalyse-cli
          - privalyse --out report.md
        artifacts:
          - report.md
```

## Azure DevOps

Add a task to your `azure-pipelines.yml`:

```yaml
steps:
- script: |
    pip install privalyse-cli
    privalyse --out $(Build.ArtifactStagingDirectory)/report.md
  displayName: 'Run Privalyse Scan'

- task: PublishBuildArtifacts@1
  inputs:
    PathtoPublish: '$(Build.ArtifactStagingDirectory)/report.md'
    ArtifactName: 'PrivacyReport'
```
