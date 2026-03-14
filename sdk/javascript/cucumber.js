module.exports = {
  default: {
    paths: ['../tests/client_sanity/features/**/*.feature'],
    require: ['tests/cucumber/**/*.ts'],
    requireModule: ['ts-node/register', 'tsconfig-paths/register'],
    format: ['progress-bar', 'json:../tests/client_sanity/artifacts/cucumber_node.json'],
    publishQuiet: true,
  },
};
