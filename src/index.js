export default {

    routes: [
        {
            pattern: /^\/$/,
            handler: () => import('./routes/index.js')
        },
        {
            pattern: /^\/users$/,
            handler: () => import('./routes/users.js')
        },
        {
            pattern: /^\/users\/u-(.+)$/,
            paramNames: ['id'],
            handler: () => import('./routes/users/u-[id].js')
        },
        {
            pattern: /^\/(.+)\/(.+)\/(.+)$/,
            paramNames: ['app', 'table', 'data'],
            handler: () => import('./routes/[app]/[table]/[data].js')
        }

    ]
}
