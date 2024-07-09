import {
	Undo,
	ClassicEditor,
	Essentials,
	Heading,
	Paragraph,
	Bold,
	Italic,
	Link,
	Indent, 
	IndentBlock,
	BlockQuote,
	CodeBlock,
	List,
} from 'ckeditor5';

ClassicEditor
	.create( document.querySelector( '#editor' ), {
		plugins: [ Undo, Essentials, Heading, Paragraph, Bold, Italic, Link, Indent, IndentBlock, BlockQuote, CodeBlock, List ],
		toolbar: [
			'undo', 'redo', '|',
			'Heading', '|',
			'bold', 'italic', 'link', 'codeBlock', '|',
			'bulletedList', 'numberedList', 'outdent', 'indent', 'blockquote'
		]
	} )
    .then( editor => {
        window.editor = editor;

        handleStatusChanges( editor );
        handleSaveButton( editor );
        handleBeforeunload( editor );
    } )
	.catch( err => {
        console.error( err.stack );
    } );

	document.querySelector( '#submit' ).addEventListener( 'click', () => {
		const editorData = editor.getData();
	})