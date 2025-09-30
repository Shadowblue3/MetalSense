let words = ["redicting", "reventing", "rotects from"];

async function interval_1(){
  await new Promise(resolve => setTimeout(resolve, 80));
}
async function interval_2(){
  await new Promise(resolve => setTimeout(resolve, 400));
}

async function main(){
  const elem = document.querySelector(".lettering");
  while(true){
    for(let i = 0; i < words.length; i++){
      let word = words[i];
      
      // type out the word
      for (const e of word) {
        await interval_1();
        elem.innerHTML += e;
      }

      await interval_2();

      // delete the word
      while(elem.innerHTML.length !== 1){
        elem.innerHTML = elem.innerHTML.slice(0,-1);
        await interval_1();
      }

      await interval_2();
    }
  }
}
main();
