import template from './template.js'

export async function render(content, data) {

	const result = template(content)

	return result;
}

