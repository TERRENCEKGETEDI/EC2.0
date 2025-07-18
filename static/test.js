let buttons=document.querySelectorAll("button");
let inputs=document.querySelectorAll("input");
buttons.forEach(button => {
    button.addEventListener("click", function() {
        if(buttons[0]===button||buttons[1]===button){
            inputs[0].value=button.textContent;
        }
        if(buttons[2]===button||buttons[3]===button){
            inputs[1].value=button.textContent;
        }
        if(buttons[4]===button||buttons[5]===button||buttons[6]===button||buttons[7]===button||buttons[8]===button||buttons[9]===button||buttons[10]===button||buttons[11]===button||buttons[12]===button||buttons[13]===button||buttons[14]===button||buttons[15]===button||buttons[16]===button||buttons[17]===button||buttons[18]===button||buttons[19]===button||buttons[20]===button||buttons[21]===button||buttons[22]===button||buttons[23]===button||buttons[24]===button||buttons[25]===button||buttons[26]===button||buttons[27]===button||buttons[28]===button||buttons[29]===button){
            inputs[2].value=button.textContent;
        }
    });
});