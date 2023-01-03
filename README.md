# JuanLesPIN

[IntelPin](https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-binary-instrumentation-tool-downloads.html) tool to detect and mitigate Windows malware evasion techniques. 

This tool is a prototype developed for the paper "[Longitudinal Study of the Prevalence of Malware Evasive Techniques](https://arxiv.org/abs/2112.11289)". 

If you use this tool in a research project, please cite:
```
@article{maffia2021longitudinal,
  title={Longitudinal Study of the Prevalence of Malware Evasive Techniques},
  author={Maffia, Lorenzo and Nisi, Dario and Kotzias, Platon and Lagorio, Giovanni and Aonzo, Simone and Balzarotti, Davide},
  journal={arXiv preprint arXiv:2112.11289},
  year={2021}
}
```



## Installation
To install this tool you will need to download first:

 - [Visual Studio](https://visualstudio.microsoft.com/) (also community edition is ok). Make sure to have C++ Windows development kit
 - Intel PIN 3.17 (you can download it from [HERE](https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-binary-instrumentation-tool-downloads.html))

Then simply follow those **5 steps**:

1. Extract the zip containing IntelPIN inside C:\ and rename it to "pin" so that you should have the pin executable at C:\pin\pin.exe

2. Change directory to C:\pin\source\tools and clone the repo.

3. Open the file C:\pin\source\tools\JuanLesPIN-Public\JuanLesPIN.sln with Visual Studio.

4. Go to *Project->Properties* inside Visual Studio menu.
Then inside *"Configuration Properties" -> C/C++ -> Preprocessor -> "Preprocessor Definitions"* ,
modify the value of the variable *_WINDOWS_H_PATH* to match your windows development kit version.

5. Build the project in Release mode x86 (the tool has been developed to work mainly on 32 bit malware)


## Usage

Now to instrument a malware with JuanLesPIN you can launch:

```
C:\pin\pin.exe -follow_execv -t C:\pin\source\tools\JuanLesPIN-Public\Release\JuanLesPIN.dll -timer 0 -report evasion-report -- <path to malware>
```
