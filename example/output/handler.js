async function GET() {
    console.log('GET');
    
}

async function POST() {
    console.log('POST');
    
}
async function PUT() {
    console.log('PUT');
    
}
async function DELETE() {
    console.log('DELETE');
    
}

var $1 = /*#__PURE__*/Object.freeze({
    __proto__: null,
    GET: GET,
    POST: POST,
    PUT: PUT,
    DELETE: DELETE
});

/* This file is auto generated from 'generateRoutes.js' file */

var manifest = {
    routes: [
        {
            pattern: /^\/$/,
            paramNames: [],
            isDynamic: false,
            isRest: false,
            view: './routes/index.html',
            handlers: [$1]
        },
    ],
	views: {
        './routes/index.html': `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
</head>
<body>
    <script>

        let lastname = 'ahmadi'

        let name= \`hadi \${lastname}\`;


    </script>
</body>
</html>`,
}
};

// {#if show}
    //     <div>Show</div>
    // {/if}
function template(md, data = {}) {


    const matched = md.match(/\{\{(\w*)\}\}/g);

	matched?.map((match) => {
		const replaceStr = match;
		const replaceWith = data[match.substring(2, match.length - 2)];

		md = md.replace(replaceStr, replaceWith);
	});

    md.replace('`', '\\`');
    md.replace('$', '\\$');

    console.log(md);
    return md
}

async function render(content, data) {

	const result = template(content);

	return result;
}

/** 
 * @param {string[]} names
 * @param {object} match
 *
 * @returns {import('./types.d.ts').Params}
 *
 * */
function getParams(names = [], match) {
    /** @type {import('./types.d.ts').Params} */
	const params = {};

	for (let i = 0; i < names.length; i++) {
		params[names[i]] = match[i + 1];
	}

	return params;
}

// TODO: route matching priority (sorting)
/**
 * @param {string} pathname
 * @param {Route[]} routes
 *
 * @returns {Route|null}
 * */
function getMatchingRoute(pathname, routes) {
	let result = null;
	// remove trailingSlach /url/ => /url
	if(pathname.endsWith('/') && pathname.length > 1) pathname = pathname.slice(0, pathname.length-1);
	
	for (const route of routes) {
		if (route.pattern.test(pathname)) {

			if(!result) {
				result = route;
			} else {
				if(result.isRest && !route.isRest) result = route;
				if(result.isDynamic && !route.isDynamic) result = route;
				if(result.isDynamic && route.isDynamic) {
					if(result.paramNames.length > route.paramNames.length) {
						result = route;
					}
				} 
			}

			
		}
	}

	if(result)
		result.params = getParams(result.paramNames, pathname.match(result.pattern));

	return result;
}

/**
 * @param {Request} request
 */
async function handler(request) {
	const { pathname } = new URL(request.url);
	const { method } = request;

	const route = getMatchingRoute(pathname, manifest.routes);

	if (!route) {
		return new Response('Not found', { status: 404 });
	}

    /** @type {RequestEvent} */
	const event = { request, params: route.params ?? {}, data: {} };

	// recursive function
    //

	function renderView(route) {
		
			return async function (event) {
				const html = manifest.views[route.view];
				if(route.handlers?.[route.handlers.length - 1]?.['GET']) {
					await route.handlers[route.handlers.length - 1]['GET'](event);
				}

				return {
					
					body: await render(html),
					headers: {
						'Content-Type': 'text/html'
					}
				}
			}
		
	
	}

    /**
     * @param {number} index
     *
     * @returns {RequestHandler}
     * */
	function getHandler(index) {
		const currentHandler = route.handlers[index];

		if(method === 'GET' && !currentHandler) {
			return renderView(route)
		}
        
		// return the actual endpoint function
		if (index === route.handlers.length - 1) {

            // return html

			if (method === 'GET' && route.view) {
				return renderView(route);
			}

			return currentHandler[method];
		}

		// return middleware function
		return (event) => currentHandler.handle?.(event, getHandler(index + 1));
	}

    const handlerFn = await getHandler(0);

    /** @type {ResponseObject} */

	const res = (await handlerFn(event)) ?? {};

	res.headers = res.headers ?? {};
	if (res.body && typeof res.body === 'object') {
		res.body = JSON.stringify(res.body);
		res.headers['Content-Type'] = 'application/json';
	}

	return new Response(res.body, {
		status: res.status,
		headers: res.headers
	});
}

export { handler as default };
