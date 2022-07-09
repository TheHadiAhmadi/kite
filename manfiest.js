/* This file is auto generated from 'generateRoutes.js' file */

import * as $1 from './routes/__middleware.js'
import * as $2 from './routes/__middleware.js'
import * as $3 from './routes/index.js'
import * as $4 from './routes/users.js'
import * as $5 from './routes/users/__middleware.js'
import * as $6 from './routes/users/[id].js'
import * as $7 from './routes/users/hadi.js'
import * as $8 from './routes/users/__middleware.js'
import * as $9 from './routes/[app]/[table]/[data].js'

export default {
    routes: [
        {
            pattern: /^\/__middleware$/,
            paramNames: [],
            handlers: [$1, $2]
        },
        {
            pattern: /^\/$/,
            paramNames: [],
            handlers: [$1, $3]
        },
        {
            pattern: /^\/users$/,
            paramNames: [],
            handlers: [$1, $4]
        },
        {
            pattern: /^\/users\/(.+)$/,
            paramNames: ["id"],
            handlers: [$1, $5, $6]
        },
        {
            pattern: /^\/users\/hadi$/,
            paramNames: [],
            handlers: [$1, $5, $7]
        },
        {
            pattern: /^\/users\/__middleware$/,
            paramNames: [],
            handlers: [$1, $5, $8]
        },
        {
            pattern: /^\/(.+)\/(.+)\/(.+)$/,
            paramNames: ["app","table","data"],
            handlers: [$1, $5, $9]
        },
    ]
}

