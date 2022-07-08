import config from './src/index.js'

function getMethod(method) {
    if(method === 'DELETE') return 'del'
    return method.toLowerCase();
}

function findRoute(pathname) {
    for(const route of config.routes) {
        if(route.pattern.test(pathname)) {
            return route;
        }
    }
    return null;
}

export default async function handler(request) {

    const url = new URL(request.url);
    const method = getMethod(request.method);

    const pathname = url.pathname;

    const r = findRoute(pathname)
    if(!r) {
        return new Response('Not found', {status: 404})
    }
    const mod = await r.handler()

    const fn = mod[method]
    
    if(!fn) {
        return new Response('Method not available', {status: 405})
    }

    try {
        const res = await fn(request)

        return new Response(res.body, {
            status: res.status,
            headers: res.headers
        })
    } catch(err) {
        console.log(err)
        return new Response(err.message, {status: 500})
    }
}

