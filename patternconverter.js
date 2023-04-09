/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  INPUT


function SanitizeInput(Input) 
{
    if (Input.length > 0)
    {
        if (Input.match(/^[a-zA-Z0-9\s\\?*]+$/g))
            return Input;
        else
        {
            alert("Invalid input!");
            return "";
        }
    }
    else
        return "";
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  IDA TO CODE


const Elements = 
{
    Debug:      document.getElementById('debug'),
    DropDown:   document.getElementById('dropdown'),
    CheckBoxM:  document.getElementById('mask'),
    CheckBoxW:  document.getElementById('white'),
};

for (const Key in Elements) 
{
    if (Object.hasOwnProperty.call(Elements, Key)) {
      const Element = Elements[Key];
      Element.addEventListener('change', () => { ToCode(); });
    }
}

function ToCode()
{
    var Mask            = document.getElementById('outmask');
    var outpat          = document.getElementById('outcode');
    var codePattern     = SanitizeInput(document.getElementById('inida').value.trim());
    const SelectedValue = Elements.DropDown.value;

    if (codePattern.length <= 0)
        return;

    switch (SelectedValue) 
    {
        case "normal":
        {
            if (Elements.CheckBoxW.checked)
            {
                codePattern = codePattern.replace(/\u003f/g, "\u003f\u003f");                                   //  replace every ? with ??
                codePattern = codePattern.replace(/[^\dA-Z\u003f]/g, '').replace(/(.{2})/g, '$1 ').trim();      //  insert a space each 2 characters in our list
                codePattern = codePattern.replace(/\u003f\u003f/g, "\u003f");                                   //  replace very ?? with ?
            }

            if (Elements.CheckBoxM.checked) 
            {
                //  show mask div
                Mask.style.display = 'block';
        
                var outmask = codePattern.slice();
                outmask = outmask.replace(/\b(?!\u003f)\b\S+/g, "x");                                           //  replace every word with x, except all starting with ?

                if (codePattern.length != 0)
                    codePattern = codePattern.split(' ').map(s => '\u005cx' + s).join(' ');

                    //  mask
                outmask = outmask.replace(/\s/g, '');                                                           //  remove every space
                //  I use textContent here to prevent XSS attacks
                Mask.textContent = outmask; 

                //  pattern
                codePattern = codePattern.replace(/\u003f/g, '00');

                codePattern = codePattern.replace(/\s/g, '');                                                   //  remove every space
                outpat.textContent = codePattern;

                if (Elements.Debug.checked && outpat.length != 0) 
                    console.log(outpat.textContent);

                if (Elements.Debug.checked && outmask.length != 0)
                    console.log(outmask); 
            }
            else
            {
                //  hide mask div
                Mask.style.display = 'none';

                if (codePattern.length != 0)
                    codePattern = codePattern.split(' ').map(s => '\u005cx' + s).join(' ');

                codePattern = codePattern.replace(/\u003f/g, '00');                                                 //  replace every ? with 00

                codePattern = codePattern.replace(/\s/g, '');                                                       //  remove every space
            
                //  I use textContent here to prevent XSS attacks
                outpat.textContent = codePattern;
            
                if (Elements.Debug.checked && outpat.length != 0)
                    console.log(outpat.textContent); 
            }
        }
        break;

        case "double?":
        {
            if (Elements.CheckBoxW.checked)
                codePattern = codePattern.replace(/[^\dA-Z\u003f]/g, '').replace(/(.{2})/g, '$1 ').trim();          //  insert a space each 2 characters in our list

            if (Elements.CheckBoxM.checked) 
            {
                //  show mask div
                Mask.style.display = 'block';
        
                var outmask = codePattern.slice();
                outmask = outmask.replace(/\b(?!\u003f)\b\S+/g, "x");                                               //  replace every word with x, except all starting with ?

                if (codePattern.length != 0)
                    codePattern = codePattern.split(' ').map(s => '\u005cx' + s).join(' ');

                //  mask
                outmask= outmask.replace(/\u003f\u003f/g, "\u003f");                                                //  replace very ?? with ?
                outmask = outmask.replace(/\s/g, '');                                                               //  remove all spaces
                //  I use textContent here to prevent XSS attacks
                Mask.textContent = outmask; 

                //  pattern
                codePattern = codePattern.replace(/\u003f\u003f/g, "00"); 

                codePattern = codePattern.replace(/\s/g, '');                                                       //  remove every space
                outpat.textContent = codePattern;

                if (Elements.Debug.checked && outpat.length != 0) 
                    console.log(outpat.textContent);

                if (Elements.Debug.checked && outmask.length != 0)
                    console.log(outmask);
            }
            else
            {
                //  hide mask div
                Mask.style.display = 'none';

                if (codePattern.length != 0)
                    codePattern = codePattern.split(' ').map(s => '\u005cx' + s).join(' ');

                codePattern = codePattern.replace(/\u003f\u003f/g, "00"); 

                codePattern = codePattern.replace(/\s/g, '');                                                       //  remove every space

                //  I use textContent here to prevent XSS attacks
                outpat.textContent = codePattern;

                if (Elements.Debug.checked && outpat.length != 0)
                    console.log(outpat.textContent); 
            }
        }
        break;

        case "asterisk":
        {
            if (Elements.CheckBoxW.checked)
            {
                codePattern = codePattern.replace(/\u002a/g, "\u002a\u002a");                                       //  replace every ? with ??
                codePattern = codePattern.replace(/[^\dA-Z\u002a]/g, '').replace(/(.{2})/g, '$1 ').trim();          //  insert a space each 2 characters in our list
                codePattern = codePattern.replace(/\u002a\u002a/g, "\u002a");                                       //  replace very ?? with ?
            }

            if (Elements.CheckBoxM.checked) 
            {
                //  show mask div
                Mask.style.display = 'block';
        
                var outmask = codePattern.slice();
                outmask = outmask.replace(/\b(?!\u002a)\b\S+/g, "x");                                               //  replace every word with x, except all starting with ?

                if (codePattern.length != 0)
                    codePattern = codePattern.split(' ').map(s => '\u005cx' + s).join(' ');

                outmask = outmask.replace(/\*/g, "?");

                    //  mask
                outmask = outmask.replace(/\s/g, '');                                                               //  remove every space
                //  I use textContent here to prevent XSS attacks
                Mask.textContent = outmask; 

                //  pattern
                codePattern = codePattern.replace(/\u002a/g, '00');

                codePattern = codePattern.replace(/\s/g, '');                                                       //  remove every space
                outpat.textContent = codePattern;

                if (Elements.Debug.checked && outpat.length != 0) 
                    console.log(outpat.textContent);

                if (Elements.Debug.checked && outmask.length != 0)
                    console.log(outmask); 
            }
            else
            {
                //  hide mask div
                Mask.style.display = 'none';

                if (codePattern.length != 0)
                    codePattern = codePattern.split(' ').map(s => '\u005cx' + s).join(' ');

                codePattern = codePattern.replace(/\u002a/g, '00');                                                     //  replace every ? with 00

                codePattern = codePattern.replace(/\s/g, '');                                                           //  remove every space
            
                //  I use textContent here to prevent XSS attacks
                outpat.textContent = codePattern;
            
                if (Elements.Debug.checked && outpat.length != 0)
                    console.log(outpat.textContent); 
            }
        }
        break;

        case "double*":
        {
            if (Elements.CheckBoxW.checked)
                codePattern = codePattern.replace(/[^\dA-Z\u002a]/g, '').replace(/(.{2})/g, '$1 ').trim();              //  insert a space each 2 characters in our list

            if (Elements.CheckBoxM.checked) 
            {
                //  show mask div
                Mask.style.display = 'block';
        
                var outmask = codePattern.slice();
                outmask = outmask.replace(/\b(?!\u002a)\b\S+/g, "x");                                                   //  replace every word with x, except all starting with ?

                if (codePattern.length != 0)
                    codePattern = codePattern.split(' ').map(s => '\u005cx' + s).join(' ');

                //  mask
                outmask = outmask.replace(/\u002a\u002a/g, "\u003f");                                                   //  replace very ** with ?
                outmask = outmask.replace(/\s/g, '');                                                                   //  remove all spaces
                //  I use textContent here to prevent XSS attacks
                Mask.textContent = outmask; 

                //  pattern
                codePattern = codePattern.replace(/\u002a\u002a/g, "00"); 

                codePattern = codePattern.replace(/\s/g, '');                                                           //  remove every space
                outpat.textContent = codePattern;

                if (Elements.Debug.checked && outpat.length != 0) 
                    console.log(outpat.textContent);

                if (Elements.Debug.checked && outmask.length != 0)
                    console.log(outmask);
            }
            else
            {
                //  hide mask div
                Mask.style.display = 'none';

                if (codePattern.length != 0)
                    codePattern = codePattern.split(' ').map(s => '\u005cx' + s).join(' ');

                codePattern = codePattern.replace(/\u002a\u002a/g, "00"); 

                codePattern = codePattern.replace(/\s/g, '');                                                           //  remove every space

                //  I use textContent here to prevent XSS attacks
                outpat.textContent = codePattern;

                if (Elements.Debug.checked && outpat.length != 0)
                    console.log(outpat.textContent); 
            }
        }
        break;

        default:
        break;
    }
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  CODE TO IDA


const Elements2 = 
{
    Debug:      document.getElementById('debug2'),
    DropDown:   document.getElementById('dropdown2'),
    CheckBoxW:  document.getElementById('white2'),
};

for (const Key in Elements2) 
{
    if (Object.hasOwnProperty.call(Elements2, Key)) {
      const Element = Elements2[Key];
      Element.addEventListener('change', () => { ToIda(); });
    }
}

function ToIda()
{
    const Debug     = document.getElementById('debug2');
    var idaPattern  = SanitizeInput(document.getElementById('incode').value);
    var Out         = document.getElementById('outida');

    if (idaPattern.length <= 0)
        return;

    const SelectedValue = Elements2.DropDown.value;
    switch (SelectedValue) {
        
        case "normal":
        {
            idaPattern = idaPattern.replace(/00/g, '?');                                                            //  replace every 00 with ?

            //  if no whitespaces is toggled
            if (Elements2.CheckBoxW.checked)
                idaPattern = idaPattern.replace(/\u005cx/g, '');                                                    //  erase every \x
            else
                idaPattern = idaPattern.replace(/\u005cx/g, ' ');                                                   //  replace every \x with a space
        
            //  I use textContent here to prevent XSS attacks
            Out.textContent = idaPattern.trim();                                                                    //  trim and output
        
            if (Debug.checked && Out.length != 0)
                console.log(Out.textContent); 
        }
        break;

        case "double?":
        {
            idaPattern = idaPattern.replace(/00/g, '??');                                                           //  replace every 00 with ??

            //  if no whitespaces is toggled
            if (Elements2.CheckBoxW.checked)
                idaPattern = idaPattern.replace(/\u005cx/g, '');                                                    //  erase every \x
            else
                idaPattern = idaPattern.replace(/\u005cx/g, ' ');                                                   //  replace every \x with a space
                    
            //  I use textContent here to prevent XSS attacks
            Out.textContent = idaPattern.trim();                                                                    //  trim and output
            
            if (Debug.checked && Out.length != 0)
                console.log(Out.textContent); 
        }
        break;

        case "asterisk":
        {
            idaPattern = idaPattern.replace(/00/g, '*');                                                            //  replace every 00 with ?

            //  if no whitespaces is toggled
            if (Elements2.CheckBoxW.checked)
                idaPattern = idaPattern.replace(/\u005cx/g, '');                                                    //  erase every \x
            else
                idaPattern = idaPattern.replace(/\u005cx/g, ' ');                                                   //  replace every \x with a space
        
            //  I use textContent here to prevent XSS attacks
            Out.textContent = idaPattern.trim();                                                                    //  trim and output
        
            if (Debug.checked && Out.length != 0)
                console.log(Out.textContent); 
        }
        break;

        case "double*":
        {
            idaPattern = idaPattern.replace(/00/g, '**');                                                           //  replace every 00 with ??

            //  if no whitespaces is toggled
            if (Elements2.CheckBoxW.checked)
                idaPattern = idaPattern.replace(/\u005cx/g, '');                                                    //  erase every \x
            else
                idaPattern = idaPattern.replace(/\u005cx/g, ' ');                                                   //  replace every \x with a space
                    
            //  I use textContent here to prevent XSS attacks
            Out.textContent = idaPattern.trim();                                                                    //  trim and output
            
            if (Debug.checked && Out.length != 0)
                console.log(Out.textContent); 
        }
        break;
    
        default:
            break;
    }
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  DEBUG CONSOLE


const console = document.getElementById('c');

//  display errors
window.onerror = function(error)
{
    console.textContent += '[ERR]: ' + error.toString() + '\r\n';  
    console.scrollIntoView({behavior: "smooth", block: "end"}); 
}

//  display logs
console.log = function(message) 
{
    console.textContent += '[MSG]: ' + message + '\r\n';
    console.scrollIntoView({behavior: "smooth", block: "end"});
}

//  test console log
function TestLog()
{
    console.log('This is a test!');
}

function ClearConsole()
{
    console.replaceChildren();
}
