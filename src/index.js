import * as $1 from './routes/index.js'
import * as $2 from './routes/users.js'
import * as $3 from './routes/users/u-[id].js'
import * as $4 from './routes/[app]/[table]/[data].js'

export default {

    routes: [
        {
            pattern: /^\/$/,
            handler: $1
        },
        {
            pattern: /^\/users$/,
            handler: $2
        },
        {
            pattern: /^\/users\/u-(.+)$/,
            paramNames: ['id'],
            handler: $3
        },
        {
            pattern: /^\/(.+)\/(.+)\/(.+)$/,
            paramNames: ['app', 'table', 'data'],
            handler: $4
        }

    ]
}
