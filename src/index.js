import * as $0 from './routes/__middleware.js'
import * as $1 from './routes/index.js'
import * as $2 from './routes/users.js'
import * as $3 from './routes/users/u-[id].js'
import * as $4 from './routes/[app]/[table]/[data].js'
import * as $5 from './routes/users/__middleware.js'

export default {

    routes: [
        {
            pattern: /^\/$/,
            handlers: [$0, $1]
        },
        {
            pattern: /^\/users$/,
            handlers: [$0, $2]
        },
        {
            pattern: /^\/users\/u-(.+)$/,
            paramNames: ['id'],
            handlers: [$0, $5, $3]
        },
        {
            pattern: /^\/(.+)\/(.+)\/(.+)$/,
            paramNames: ['app', 'table', 'data'],
            handlers: [$0, $4]
        }
    ]
}
