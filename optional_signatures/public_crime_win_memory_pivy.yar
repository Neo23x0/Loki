//https://github.com/jackcr


rule memory_pivy

{

   strings:
      $a = {00 00 00 00 00 00 00 00 00 00 00 53 74 75 62 50 61 74 68 00} // presence of pivy in memory

   condition: 
      any of them

}