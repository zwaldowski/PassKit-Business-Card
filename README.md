# PassKit-Business-Card
> A template that can be used to generate passes for the iOS Wallet app that can be used like business cards.

<p align="center">
	<img src="demo.png" style="margin: 0 auto; width: 500px;"/>
	<img src="demo-back.png" style="margin: 0 auto; width: 500px;"/>
</p>

A new trend that's been emerging in recent years is taking the pass features of the [Wallet](https://support.apple.com/en-us/HT204003) app, available on every iPhone, and using them in new and interesting ways.

One novel idea is the concept of having a pass that serves as a virtual business card. Anyone with an iPhone is guaranteed to have the app installed, it's easier than carrying physical cards around, and it usually leaves a lasting impression.

This repository is a basic template indicating all of the metadata and assets needed to create a business card. It also contains a compiled version of the utility that Apple published that allows pass bundles to be properly signed with a Developer certificate so they'll work on consumer hardware.

I can't take credit for this idea. A major shoutout goes to [Thi Doan](http://twitter.com/thi_dev) for originally sharing his virtual business card with me. :)

# Requirements

* An active, paid Apple Developer subscription.
* A text editing app.
* A graphics editing app.

# Generating a Signing Certificate
Before the pass will work on any device (Even the iOS Simulator), it is necessary to sign it with a certificate issued by Apple.

1. Go to your [Apple Developer Account](https://developer.apple.com/account/).
2. Go to 'Certificates, Identifiers & Profiles' and click on 'Pass Type IDs'.
3. Create a new Pass Type ID, specifying an appropriate identifier string.
4. Go to Certificates, click on '+', and select a 'Pass Type ID Certificate'.
5. Select your previously created Pass Type ID, and follow the steps to generate a certificate and import it into your Mac's security keychain.

# Configuring Your Pass
All of the information and configuration settings for a pass are located in the `pass.json` file.

To align the pass template with the signing certificate generated by Apple, open `pass.json` and:

* For `passTypeIdentifier`, paste in the identifier string you chose in the 'Pass Type IDs' panel.
* For `teamIdentifier`, go to the [Membership panel](https://developer.apple.com/account/#/membership/) in your Apple Developer account, and copy the code in your 'Team ID' row.

# Building Your Pass
Once `pass.json` is configured with your Pass Type ID and Team ID, and you've installed the certificate in your keychain, you can use the `signpass` utility to generate a pass.

Open Terminal, navigate to this project folder, and then run
```
./signpass -p PassKit-Business-Card
```

If all goes well, this will generate a `PassKit-Business-Card.pkpass` file in the same folder.

# Testing Your Pass
Once a pass has been generated, you can test it in the iOS Simulator. Simply open any of the iPhone device simulators, and drag the `.pkpass` file over the Simulator window. If the pass was set up correctly, it will then automatically display in the Simulator. If it fails, nothing will happen.

# Debugging Your Pass
If dragging the `.pkpass` file into the iOS Simulator does nothing, you can open the 'Console' app on your Mac, to view the device logs of the iOS Simulator. Each time you try and import the `.pkpass` file, an error message with the reason why it failed will appear in the log.

# More Information
* For Apple's documentation on creating passes, check the [Introducing Wallet](https://developer.apple.com/library/content/documentation/UserExperience/Conceptual/PassKit_PG/index.html#//apple_ref/doc/uid/TP40012195-CH1-SW1) page on the Apple Developer Website.
* For more information on the types of keys allowed in `pass.json`, check the [Top-Level Keys](https://developer.apple.com/library/content/documentation/UserExperience/Reference/PassKit_Bundle/Chapters/TopLevel.html) page on the Apple Developer website.
* For sample passes, as well as the source code for `signpass`, check out [this sample code download](https://developer.apple.com/services-account/download?path=/iOS/Wallet_Support_Materials/WalletCompanionFiles.zip).

# License

All of the code in this repository is released under public domain. No credit is necessary.
