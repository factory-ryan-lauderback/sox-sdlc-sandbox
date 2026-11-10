# Tiltfile for Acme Lending environments.
#
# CI mode (SOX_ENV_SPEC set; the only mode that produces SOX evidence): deploy the images pinned
# by digest in the environment spec. No image builds and no live_update, so what runs is exactly
# what the build step attested. Object definitions come from tools/sox_release/kube.py, the same
# renderer the deploy train uses for production.
#
# Dev mode (laptop): build each service locally and deploy all three. Outside the SOX path.
analytics_settings(False)

spec_path = os.getenv('SOX_ENV_SPEC', '')
if spec_path:
    deps = decode_json(str(local(['python3', '-m', 'tools.sox_release.kube', 'deps', '--spec', spec_path], quiet=True, echo_off=True)))
    k8s_yaml(local(['python3', '-m', 'tools.sox_release.kube', 'render', '--spec', spec_path], quiet=True, echo_off=True))
    for name in deps:
        k8s_resource(name, resource_deps=deps[name])
else:
    for name in ['db', 'api', 'ui']:
        docker_build('acme-lending/' + name, 'services/' + name)
    k8s_yaml(local(['python3', '-m', 'tools.sox_release.kube', 'render-dev'], quiet=True))
    k8s_resource('api', resource_deps=['db'])
    k8s_resource('ui', resource_deps=['api'])
