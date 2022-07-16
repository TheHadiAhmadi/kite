// {#if show}
    //     <div>Show</div>
    // {/if}
export default function template(md, data = {}) {


    const matched = md.match(/\{\{(\w*)\}\}/g);

	matched?.map((match) => {
		const replaceStr = match;
		const replaceWith = data[match.substring(2, match.length - 2)];

		md = md.replace(replaceStr, replaceWith);
	});

    md.replace('`', '\\`')
    md.replace('$', '\\$')

    console.log(md)
    return md
}
