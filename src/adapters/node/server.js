import http from 'http'
import {Request, Response, Headers} from 'undici'
import { getRequest, setResponse} from './helpers'
import handler from 'HANDLER'

global.Response = Response
global.Headers = Headers
global.Request = Request;

http.createServer(async (req, res) => {
    const request = getRequest(req)

    const response = await handler(request)

    setResponse(res, response)
}).listen(3000)
