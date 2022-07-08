import manifest from './manfiest.js';
import { getMatchingRoute, getMethod } from './utils.ts';


export default async function handler(request: Request) {
	const { pathname } = new URL(request.url);
	const method = getMethod(request.method);

	const route = getMatchingRoute(pathname, manifest.routes as unknown as Route[]);

	if (!route) {
		return new Response('Not found', { status: 404 });
	}

	const event: RequestEvent = { request, params: route.params ?? {} };

	// recursive function
	function getHandler(index: number): RequestHandler {
		const currentHandler = route.handlers[index];
        
		// return the actual endpoint function
		if (index === route.handlers.length - 1) {

            // return html
			if (method === 'get' && currentHandler['default']) {
				return async (event: RequestEvent) => {
					const res = await currentHandler['default']({
						...event,
						getData: async () => {
							const res = await currentHandler['get'](event);
							return res.body;
						}
					});
					return {
						body: res
					};
				};
			}
			return currentHandler[method];
		}

		// return middleware function
		return (event) => currentHandler.handle!(event, getHandler(index + 1));
	}

	const res: ResponseObject = (await getHandler(0)(event)) as ResponseObject;

	console.log(res);

	res.headers = res.headers ?? {};
	if (res.body && typeof res.body === 'object') {
		res.body = JSON.stringify(res.body);
		res.headers['Content-Type'] = 'application/json';
	}

	return new Response(res.body, {
		status: res.status,
		headers: res.headers as Headers
	});
}
