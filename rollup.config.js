import commonjs from '@rollup/plugin-commonjs'
import resolve from '@rollup/plugin-node-resolve'
import fs from 'fs'

if(!fs.existsSync('./dist')) fs.mkdirSync('./dist')
fs.copyFileSync('./package.json', './dist/package.json')

export default [{
    input: './src/handler.js',
    output: {
        file: './dist/handler.js',
        format: 'esm',
    },
    external: ['MANIFEST']
}, {
    input: './src/adapters/node/server.js',
    output: {
        file: './dist/adapters/node/server.js',
        format: 'esm'
    },
    plugins: [
        resolve(),
        commonjs(),
    ]
}, {
    input: './src/adapters/deno/server.js',
    output: {
        file: './dist/adapters/deno/server.js',
        format: 'esm'
    }
}, {
    input: './rollup.js',
    output: {
        file: './dist/rollup.js',
        format: 'esm'
    },
    plugins: [
        resolve(),
        commonjs()
    ]
}]
