import {serve} from 'https://deno.land/std/http/server.ts'

import handler from '../handler.js'

serve((req) => {
    return handler(req)

}, {port: 3000})
