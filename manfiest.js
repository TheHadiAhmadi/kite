/* This file is auto generated from 'generateRoutes.js' file */

import * as $1 from './routes/__middleware.js'
import * as $2 from './routes/[...all].js'
import * as $3 from './routes/__middleware.js'
import * as $4 from './routes/index.js'
import * as $5 from './routes/users.js'
import * as $6 from './routes/users/__middleware.js'
import * as $7 from './routes/users/[id].js'
import * as $8 from './routes/users/__middleware.js'
import * as $9 from './routes/users/hadi.js'
import * as $10 from './routes/[app]/[table]/[data].js'

export default {
    routes: [
        {
            pattern: /^\/(.+)$/,
            paramNames: ["[...all"],
            isDynamic: true,
            isRest: true,
            handlers: [$1, $2]
        },
        {
            pattern: /^\/__middleware$/,
            paramNames: [],
            isDynamic: false,
            isRest: false,
            handlers: [$1, $3]
        },
        {
            pattern: /^\/$/,
            paramNames: [],
            isDynamic: false,
            isRest: false,
            handlers: [$1, $4]
        },
        {
            pattern: /^\/users$/,
            paramNames: [],
            isDynamic: false,
            isRest: false,
            handlers: [$1, $5]
        },
        {
            pattern: /^\/users\/(\w+)$/,
            paramNames: ["id"],
            isDynamic: true,
            isRest: false,
            handlers: [$1, $6, $7]
        },
        {
            pattern: /^\/users\/__middleware$/,
            paramNames: [],
            isDynamic: false,
            isRest: false,
            handlers: [$1, $6, $8]
        },
        {
            pattern: /^\/users\/hadi$/,
            paramNames: [],
            isDynamic: false,
            isRest: false,
            handlers: [$1, $6, $9]
        },
        {
            pattern: /^\/(\w+)\/(\w+)\/(\w+)$/,
            paramNames: ["app","table","data"],
            isDynamic: true,
            isRest: false,
            handlers: [$1, $6, $10]
        },
    ]
}

