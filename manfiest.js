
import * as $1 from './src/routes/__middleware.js'
import * as $2 from './src/routes/users.js'
import * as $3 from './src/routes/index.js'
import * as $4 from './src/routes/__middleware.js'
import * as $5 from './src/routes/users/__middleware.js'
import * as $6 from './src/routes/users/__middleware.js'
import * as $7 from './src/routes/users/u-[id].js'
import * as $8 from './src/routes/[app]/[table]/[data].js'

export default {
    routes: [
        {
            pattern: /^\/users$/,
            paramNames: [],
            handlers: [$1, $2]
        },
        {
            pattern: /^\/$/,
            paramNames: [],
            handlers: [$1, $3]
        },
        {
            pattern: /^\/__middleware$/,
            paramNames: [],
            handlers: [$1, $4]
        },
        {
            pattern: /^\/users\/__middleware$/,
            paramNames: [],
            handlers: [$1, $5, $6]
        },
        {
            pattern: /^\/users\/u-(.+)$/,
            paramNames: ["id"],
            handlers: [$1, $5, $7]
        },
        {
            pattern: /^\/(.+)\/(.+)\/(.+)$/,
            paramNames: ["app","table","data"],
            handlers: [$1, $5, $8]
        },
    ]
}

