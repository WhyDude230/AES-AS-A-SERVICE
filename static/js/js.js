'use scrict';

var linenumbers = document.getElementById('line-numbers');

var editor = document.getElementById('codeblock');

function getWidth(elem) {

	return elem.scrollWidth - (parseFloat(window.getComputedStyle(elem, null).getPropertyValue('padding-left')) + parseFloat(window.getComputedStyle(elem, null).getPropertyValue('padding-right')))

}

function getFontSize(elem) {

	return parseFloat(window.getComputedStyle(elem, null).getPropertyValue('font-size'));

}

function cutLines(lines) {

	return lines.split(/\r?\n/);

}





function getLineHeight(elem) {

	var computedStyle = window.getComputedStyle(elem);

	var lineHeight = computedStyle.getPropertyValue('line-height');

	var lineheight;



	if (lineHeight === 'normal') {

		var fontSize = computedStyle.getPropertyValue('font-size');

		lineheight = parseFloat(fontSize) * 1.2;

	} else {

		lineheight = parseFloat(lineHeight);

	}



	return lineheight;

}

function getTotalLineSize(size, line, options) {

	if (typeof options === 'object') options = {};

	var p = document.createElement('span');

	p.style.setProperty('white-space', 'pre');

	p.style.display = 'inline-block';

	if (typeof options.fontSize !== 'undefined') p.style.fontSize = options.fontSize;

	p.innerHTML = line;

	document.body.appendChild(p);

	var result = (p.scrollWidth / size);

	p.remove();

	return Math.ceil(result);

}

function getLineNumber() {

	var textLines = editor.value.substr(0, editor.selectionStart).split("\n");

	var currentLineNumber = textLines.length;

	var currentColumnIndex = textLines[textLines.length - 1].length;

	return currentLineNumber;

}



function init() {

	var totallines = cutLines(editor.value), linesize;

	linenumbers.innerHTML = '';

	for (var i = 1; i <= totallines.length; i++) {

		var num = document.createElement('p');

		num.innerHTML = i;

		linenumbers.appendChild(num);



		linesize = getTotalLineSize(getWidth(editor), totallines[(i - 1)], { 'fontSize': getFontSize(editor) });

		if (linesize > 1) {

			num.style.height = (linesize * getLineHeight(editor)) + 'px';

		}

	}



	linesize = getTotalLineSize(getWidth(editor), totallines[(getLineNumber() - 1)], { 'fontSize': getFontSize(editor) });

	if (linesize > 1) {

		linenumbers.childNodes[(getLineNumber() - 1)].style.height = (linesize * getLineHeight(editor)) + 'px';

	}



	editor.style.height = editor.scrollHeight;

	linenumbers.style.height = editor.scrollHeight;

}

editor.addEventListener('keyup', init);
editor.addEventListener('input', init);
editor.addEventListener('click', init);
editor.addEventListener('paste', init);
editor.addEventListener('mouseover', init);
editor.addEventListener('focus', init);

editor.click();


/*	For Demo Only */

editor.innerHTML = `Enter Your text here to be encrypted
`;