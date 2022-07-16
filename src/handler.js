import manifest from 'MANIFEST';
import { render } from './utils/render.js';
import { getMatchingRoute } from './utils/utils.js';

/**
 * @param {Request} request
 */
export default async function handler(request) {
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
				let data ={}
				if(route.handlers?.[route.handlers.length - 1]?.['GET']) {
					const {body} = await route.handlers[route.handlers.length - 1]['GET'](event);
					data = body
				}

				return {
					
					body: await render(html, data),
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
