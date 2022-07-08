
type Params = Record<string, string>;
type Method = 'get' | 'put' | 'post' | 'del';

type RequestEvent = {
	request: Request;
	params: Params;
	getData?: any;
};

type ResponseObject = {
	body?: string;
	status?: number;
	headers?: Headers | object | any;
};

type RequestHandler = (event: RequestEvent) => Promise<ResponseObject>;
type Handler = {
	get?: RequestHandler;
	post?: RequestHandler;
	put?: RequestHandler;
	del?: RequestHandler;
	default?: (event: any) => string;
	handle: (event: RequestEvent, next: RequestHandler) => Promise<ResponseObject>;
};

type Route = {
	pattern: RegExp;
	handlers: Handler[];
	paramNames?: string[];
	params?: Params;
};