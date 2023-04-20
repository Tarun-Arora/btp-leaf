// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "helper.h"

using namespace std;
using namespace seal;

int main()
{
    cout << "Microsoft SEAL version: " << SEAL_VERSION << endl;

    leaf_example();
    
    cout << "\n";
    size_t megabytes = MemoryManager::GetPool().alloc_byte_count() >> 20;
    cout << "[" << setw(7) << right << megabytes << " MB] "
         << "Total allocation from the memory pool" << endl;

    return 0;
}
