//
//  ViewController.m
//  BitcodeEvaluation
//
//  Created by Zhuowei Zhang on 2018-10-14.
//  Copyright © 2018 Zhuowei Zhang. All rights reserved.
//

#import "ViewController.h"
#include <mach-o/loader.h>
#include <mach-o/ldsyms.h>

@interface ViewController ()

@end
/**
 * Reads this app's main executable from disk, and replace the encrypted section with
 * the decrypted data found in our own memory.
 */
static NSData* exportOwnExecutable(void (^reportError)(NSString* error)) {
    
    // This basically works the same way as Clutch and other application dumping
    // tools, except, of course, this can only dump itself.
    
    // should we raise an error if the executable isn't encrypted?
    BOOL needsEnc = NO;
    // Pointer to this current executable's encryption info
    struct encryption_info_command_64* enc_cmd = nil;
    // find the first load command in this executable
    struct load_command* cmd = (struct load_command*) (((char*)&_mh_execute_header) + sizeof(struct mach_header_64));
    // and search through all load commands in this executable.
    for (int i = 0; i < _mh_execute_header.ncmds; i++) {
        if (cmd->cmd == LC_ENCRYPTION_INFO_64) {
            enc_cmd = (struct encryption_info_command_64*)cmd;
            break;
        }
        struct load_command* ncmd = (struct load_command*) (((char*)cmd) + cmd->cmdsize);
        cmd = ncmd;
    }
    // If we didn't find an encryption command, executable isn't encrypted.
    // show an error if that's enabled.
    if (needsEnc && !enc_cmd) {
        reportError(@"Not encrypted");
        return nil;
    }
    
    // now, load the original executable from disk
    NSBundle* bundle = [NSBundle mainBundle];
    NSMutableData* mainExecutableData = [NSMutableData dataWithContentsOfURL:bundle.executableURL];
    
    if (!mainExecutableData) {
        reportError(@"Can't load executable from disk");
        return nil;
    }
    
    // check that the original executable is Mach-O. (I don't handle multiarch files yet)
    const uint32_t* executableData = mainExecutableData.bytes;
    if (executableData[0] != MH_MAGIC_64) {
        reportError(@"Wrong magic number");
        return nil;
    }
    
    // If we found the encrypted section, replace the encrypted data with
    // the decrypted copy found in our own memory.
    if (enc_cmd) {
        [mainExecutableData replaceBytesInRange:NSMakeRange(enc_cmd->cryptoff, enc_cmd->cryptsize) withBytes:((char*)&_mh_execute_header) + enc_cmd->cryptoff length:enc_cmd->cryptsize];
    }
    
    // and finally return the data.
    return mainExecutableData;
}

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
}

- (IBAction)exportPressed {
    // runs when the Export button is pressed.
    // stores any error messages from the dumping routine.
    __block NSString* errorString = nil;
    // runs the dumping code.
    NSData* exportedData = exportOwnExecutable(^(NSString* err) {
        errorString = err;
    });
    // if there was an error, display the error.
    if (errorString) {
        UIAlertController* alertController = [UIAlertController alertControllerWithTitle:@"Error during export" message:errorString preferredStyle:UIAlertControllerStyleAlert];
        [alertController addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alertController animated:YES completion:nil];
        return;
    }
    // bring up a share screen of the exported data.
    UIActivityViewController* activityController = [[UIActivityViewController alloc] initWithActivityItems:@[exportedData] applicationActivities:nil];
    [self presentViewController:activityController animated:YES completion:nil];
}

/**
 This function is't called anywhere: it's included to see how stack canaries work.
 */
+ (void)worksWithBuffers:(const char*)anotherString {
    char temp[0x100];
    // this just stores a string into temp, then prints the string to debugger
    snprintf(temp, sizeof(temp), "Oh, hi, %s", anotherString);
    puts(temp);
}

@end
