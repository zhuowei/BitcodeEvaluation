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
static NSData* exportOwnExecutable(void (^reportError)(NSString* error)) {
    BOOL needsEnc = NO;
    struct encryption_info_command_64* enc_cmd = nil;
    struct load_command* cmd = (struct load_command*) (((char*)&_mh_execute_header) + sizeof(struct mach_header_64));
    for (int i = 0; i < _mh_execute_header.ncmds; i++) {
        if (cmd->cmd == LC_ENCRYPTION_INFO_64) {
            enc_cmd = (struct encryption_info_command_64*)cmd;
            break;
        }
        struct load_command* ncmd = (struct load_command*) (((char*)cmd) + cmd->cmdsize);
        cmd = ncmd;
    }
    if (needsEnc && !enc_cmd) {
        return nil;
    }
    
    NSBundle* bundle = [NSBundle mainBundle];
    NSMutableData* mainExecutableData = [NSMutableData dataWithContentsOfURL:bundle.executableURL];
    
    if (!mainExecutableData) {
        reportError(@"Can't load executable from disk");
        return nil;
    }
    
    const uint32_t* executableData = mainExecutableData.bytes;
    if (executableData[0] != MH_MAGIC_64) {
        reportError(@"Wrong magic number");
        return nil;
    }
    
    if (enc_cmd) {
        [mainExecutableData replaceBytesInRange:NSMakeRange(enc_cmd->cryptoff, enc_cmd->cryptsize) withBytes:((char*)&_mh_execute_header) + enc_cmd->cryptoff length:enc_cmd->cryptsize];
    }
    
    return mainExecutableData;
}

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
}

- (IBAction)exportPressed {
    __block NSString* errorString = nil;
    NSData* exportedData = exportOwnExecutable(^(NSString* err) {
        errorString = err;
    });
    if (errorString) {
        UIAlertController* alertController = [UIAlertController alertControllerWithTitle:@"Error during export" message:errorString preferredStyle:UIAlertControllerStyleAlert];
        [alertController addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alertController animated:YES completion:nil];
        return;
    }
    UIActivityViewController* activityController = [[UIActivityViewController alloc] initWithActivityItems:@[exportedData] applicationActivities:nil];
    [self presentViewController:activityController animated:YES completion:nil];
}

@end
