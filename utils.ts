
export function getMethod(method: string): Method {
	if (method === 'DELETE') return 'del';
	return method.toLowerCase() as Method;
}

export function getParams(names: string[] = [], match: object): Params {
	const params: Params = {};

	for (let i = 0; i < names.length; i++) {
		params[names[i]] = match[i + 1];
	}

	return params;
}

// TODO: route matching priority (sorting)
export function getMatchingRoute(pathname: string, routes: Route[]): Route | null {
	for (const route of routes) {
		if (route.pattern.test(pathname)) {
			route.params = getParams(route.paramNames, pathname.match(route.pattern));
			return route;
		}
	}
	return null;
}
