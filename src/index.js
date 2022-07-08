export default {

    routes: [
        {
            pattern: /^\/$/,
            handler: () => import('./routes/index.js')
        }

    ]
}
