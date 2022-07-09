import manifest from './manfiest.js';
import { getMatchingRoute, getMethod } from './utils.js';


/**
 * @param {Request} request
 */
export default async function handler(request) {
	const { pathname } = new URL(request.url);
	const method = getMethod(request.method);

	const route = getMatchingRoute(pathname, manifest.routes);

	if (!route) {
		return new Response('Not found', { status: 404 });
	}

    /** @type {RequestEvent} */
	const event = { request, params: route.params ?? {} };

	// recursive function
    //
    /**
     * @param {number} index
     *
     * @returns {RequestHandler}
     * */
	function getHandler(index) {
		const currentHandler = route.handlers[index];
        
		// return the actual endpoint function
		if (index === route.handlers.length - 1) {

            // return html
			if (method === 'get' && currentHandler['default']) {
				return async (event) => {
					const res = await currentHandler['default']({
						...event,
						getData: async () => {
							const res = await currentHandler['get'](event);
							return res.body;
						}
					});
					return {
						body: res,
                        headers: {
                            'Content-Type': "text/html"
                        }
					};
				};
			}
			return currentHandler[method];
		}

		// return middleware function
		return (event) => currentHandler.handle?.(event, getHandler(index + 1));
	}

    const handlerFn = await getHandler(0);

    /** @type {ResponseObject} */

	const res = await handlerFn(event);

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
