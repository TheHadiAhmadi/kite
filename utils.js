
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
	let result = null
	// remove trailingSlach /url/ => /url
	if(pathname.endsWith('/')) pathname = pathname.slice(0, pathname.length-1)
	
	for (const route of routes) {
		if (route.pattern.test(pathname)) {

			console.log('matched', route.pattern)
			if(!result) {
				result = route
			} else {
				if(result.isRest && !route.isRest) result = route;
				if(result.isDynamic && !route.isDynamic) result = route;
				if(result.isDynamic && route.isDynamic) {
					if(result.paramNames.length > route.paramNames.length) {
						result = route;
					}
				} 
				// choose a route between two candidates
				console.log("choose between", route.pattern, result.pattern)
			}

			
		}
	}

	if(result)
		result.params = getParams(result.paramNames, pathname.match(result.pattern))

	return result;
}
