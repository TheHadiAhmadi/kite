import config from './src/index.js'

function getMethod(method) {
    if(method === 'DELETE') return 'del'
    return method.toLowerCase();
}

function getParams(names = [], match) {
    const params = {}

    for(let i=0; i<names.length; i++) {
        params[names[i]] = match[i+1]
    }

    return params
}

// TODO: route matching priority (sorting)
function getMatchingRoute(pathname, routes) {
    for(const route of routes) {
        if(route.pattern.test(pathname)) {
            route.params = getParams(route.paramNames, pathname.match(route.pattern))
            return route;
        }
    }
    return null;
}

export default async function handler(request) {

    const url = new URL(request.url);
    const method = getMethod(request.method);

    const pathname = url.pathname;

    const route = getMatchingRoute(pathname, config.routes)

    if(!route) {
        return new Response('Not found', {status: 404})
    }
    const fn = route.handler[method]
    
    if(!fn) {
        return new Response('Method not available', {status: 405})
    }

    try {
        const res = await fn({request, params: route.params})

        res.headers = res.headers ?? {}

        if(res.body && typeof res.body === 'object') {
            res.body = JSON.stringify(res.body)
            res.headers['Content-Type'] = 'application/json'
        }

        return new Response(res.body, {
            status: res.status,
            headers: res.headers
        })
    } catch(err) {
        console.log(err)
        return new Response(err.message, {status: 500})
    }
}

