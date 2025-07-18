for(let i=0;i<document.getElementsByTagName('textarea').length;i++){
    const textarea = document.getElementsByTagName('textarea')[i];
    
    textarea.addEventListener('input', () => {
        textarea.style.height = 'auto';
        textarea.style.height = textarea.scrollHeight + 'px';
        textarea.style.maxHeight = "70vh";
        textarea.style.overflowY = "auto";
    });
}