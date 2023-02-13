const { execSync } = require('child_process');

const NPM_ARGS = process.argv.slice(2);
const NPM_COMMAND = process.env.npm_lifecycle_event;
const VADE_PLUGINS = [
  'vade-evan-cl',
  'vade-evan-bbs',
  'vade-sidetree',
  'vade-jwt-vc',
];
const VADE_WASM_FOLDER = 'src/vade/wasm';

const jest = ({
  debug, files, silent, verbose,
} = {}) => ([
  'node',
  debug ? '--inspect' : '',
  './node_modules/.bin/jest',
  // '--all',
  // '--forceExit',
  '--runInBand',
  silent ? '--silent' : '',
  verbose ? '--verbose' : '',
  ...(files ? [files] : []),
].join(' '));
const tsProject = '-p ./tsconfig.build.json';
const tscPaths = `tscpaths ${tsProject} -s ./src -o ./dist/src > /dev/null`;
const copyVadeFiles = `rm -rf dist/${VADE_WASM_FOLDER} && cp -r ${VADE_WASM_FOLDER} dist/${VADE_WASM_FOLDER}`;
const buildTypescript = `tsc ${tsProject} && ${tscPaths} && ${copyVadeFiles}`;
const fixFunctionArgName = [
  'vade_evan.js',
  'vade_evan.d.ts',
]
  .map((file) => `sed -i '' -E 's/function([,:])/functionName\\1/g' ${VADE_WASM_FOLDER}/${file}`)
  .join(' && ');
const buildWasm = (buildForBrowser) => [
  'wasm-pack',
  'build',
  `${__dirname}/../..`,
  '--release',
  `--target ${buildForBrowser ? 'web' : 'nodejs'}`,
  `--out-dir ${__dirname}/${VADE_WASM_FOLDER}`,
  '--',
  '--no-default-features',
  '--features bundle-default,target-wasm',
  '&&',
  fixFunctionArgName,
].join(' ');
const buildTypings = VADE_PLUGINS
  .map((plugin) => {
    const typings = `${__dirname}/../../../${plugin}/typings`;
    const typingsDest = `./src/vade/typings/${plugin}`;
    return `rm -rf ${typingsDest} && cp -r ${typings} ${typingsDest}`;
  })
  .join(' && ');

const scripts = {
  scripts: {
    build: {
      default: [buildWasm(), buildTypings, buildTypescript].join(' && '),
      typescript: buildTypescript,
      typings: buildTypings,
      'wasm-browser': buildWasm(true),
      'wasm-node': buildWasm(),
    },
    lint: 'eslint src',
    start: [buildTypescript, 'node ./dist/src/index.js'].join(' && '),
    test: jest(),
  },
};

let toRun = NPM_COMMAND
  .split(':')
  .reduce((prev, curr) => prev[curr] || {}, scripts.scripts);
// get default section, if any
if (typeof toRun === 'object') {
  toRun = toRun.default;
}
if (typeof toRun === 'string') {
  // string commands get arguments appended
  toRun = `npx ${toRun} ${NPM_ARGS.join(' ')}`;
} else if (typeof toRun === 'function') {
  // functions commands handle arguments themselves
  toRun = `npx ${toRun()}`;
} else {
  throw new Error(`unknown script or invalid config for: ${NPM_COMMAND}`);
}

try {
  execSync(toRun, { stdio: 'inherit' });
} catch (ex) {
  // eslint-disable-next-line no-console
  console.error(ex.message);
  process.exit(1);
}
