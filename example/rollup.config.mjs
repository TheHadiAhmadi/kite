import kite from 'ht-kit/rollup.js'

/** @type {import('rollup').RollupOptions} */
export default kite({
    routes: './routes',
    adapter: 'deno',
    output: './output'
})
