
/**
 * @param {string} method
 * @returns {Method}
 *
 * */
export function getMethod(method) {
	if (method === 'DELETE') return 'del';
	return method.toLowerCase();
}

/** 
 * @param {string[]} names
 * @param {object} match
 *
 * @returns {import('./types.d.ts').Params}
 *
 * */
export function getParams(names = [], match) {
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
export function getMatchingRoute(pathname, routes) {
	for (const route of routes) {
		if (route.pattern.test(pathname)) {
			route.params = getParams(route.paramNames, pathname.match(route.pattern));
			return route;
		}
	}
	return null;
}
