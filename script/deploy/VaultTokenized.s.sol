// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.25;

import {Script, console2} from "forge-std/Script.sol";

import {Vault} from "../../src/contracts/vault/Vault.sol";

import {IMigratablesFactory} from "../../src/interfaces/common/IMigratablesFactory.sol";
import {IVault} from "../../src/interfaces/vault/IVault.sol";
import {IVaultTokenized} from "../../src/interfaces/vault/IVaultTokenized.sol";
import {IVaultConfigurator} from "../../src/interfaces/IVaultConfigurator.sol";
import {IBaseDelegator} from "../../src/interfaces/delegator/IBaseDelegator.sol";
import {INetworkRestakeDelegator} from "../../src/interfaces/delegator/INetworkRestakeDelegator.sol";
import {IFullRestakeDelegator} from "../../src/interfaces/delegator/IFullRestakeDelegator.sol";
import {IOperatorSpecificDelegator} from "../../src/interfaces/delegator/IOperatorSpecificDelegator.sol";
import {IOperatorNetworkSpecificDelegator} from "../../src/interfaces/delegator/IOperatorNetworkSpecificDelegator.sol";
import {IBaseSlasher} from "../../src/interfaces/slasher/IBaseSlasher.sol";
import {ISlasher} from "../../src/interfaces/slasher/ISlasher.sol";
import {IVetoSlasher} from "../../src/interfaces/slasher/IVetoSlasher.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {Subnetwork} from "../../src/contracts/libraries/Subnetwork.sol";

contract VaultTokenizedScript is Script {
    function run(
        address vaultConfigurator,
        address owner,
        address collateral,
        address burner,
        uint48 epochDuration,
        address[] calldata whitelistedDepositors,
        uint256 depositLimit,
        string calldata name,
        string calldata symbol,
        uint64 delegatorIndex,
        address hook,
        address network,
        uint256 networkLimit,
        bool withSlasher,
        uint64 slasherIndex,
        uint48 vetoDuration
    ) public {
        vm.startBroadcast();
        (, , address deployer) = vm.readCallers();

        bool depositWhitelist = whitelistedDepositors.length != 0;

        bytes memory vaultParams = abi.encode(
            IVaultTokenized.InitParamsTokenized({
                baseParams: IVault.InitParams({
                    collateral: collateral,
                    burner: burner,
                    epochDuration: epochDuration,
                    depositWhitelist: depositWhitelist,
                    isDepositLimit: depositLimit != 0,
                    depositLimit: depositLimit,
                    defaultAdminRoleHolder: depositWhitelist ? deployer : owner,
                    depositWhitelistSetRoleHolder: owner,
                    depositorWhitelistRoleHolder: owner,
                    isDepositLimitSetRoleHolder: owner,
                    depositLimitSetRoleHolder: owner
                }),
                name: name,
                symbol: symbol
            })
        );

        address[] memory networkLimitSetRoleHolders = new address[](2);
        networkLimitSetRoleHolders[0] = owner;
        // temporarily add deployer to set network limit
        networkLimitSetRoleHolders[1] = deployer;

        address[] memory operatorNetworkLimitSetRoleHolders = new address[](1);
        operatorNetworkLimitSetRoleHolders[0] = owner;

        address[] memory operatorNetworkSharesSetRoleHolders = new address[](1);
        operatorNetworkSharesSetRoleHolders[0] = owner;

        bytes memory delegatorParams;
        if (delegatorIndex == 0) {
            delegatorParams = abi.encode(
                INetworkRestakeDelegator.InitParams({
                    baseParams: IBaseDelegator.BaseParams({
                        defaultAdminRoleHolder: owner,
                        hook: hook,
                        hookSetRoleHolder: owner
                    }),
                    networkLimitSetRoleHolders: networkLimitSetRoleHolders,
                    operatorNetworkSharesSetRoleHolders: operatorNetworkSharesSetRoleHolders
                })
            );
        } else if (delegatorIndex == 1) {
            delegatorParams = abi.encode(
                IFullRestakeDelegator.InitParams({
                    baseParams: IBaseDelegator.BaseParams({
                        defaultAdminRoleHolder: owner,
                        hook: hook,
                        hookSetRoleHolder: owner
                    }),
                    networkLimitSetRoleHolders: networkLimitSetRoleHolders,
                    operatorNetworkLimitSetRoleHolders: operatorNetworkLimitSetRoleHolders
                })
            );
        } else if (delegatorIndex == 2) {
            delegatorParams = abi.encode(
                IOperatorSpecificDelegator.InitParams({
                    baseParams: IBaseDelegator.BaseParams({
                        defaultAdminRoleHolder: owner,
                        hook: hook,
                        hookSetRoleHolder: owner
                    }),
                    networkLimitSetRoleHolders: networkLimitSetRoleHolders,
                    operator: owner
                })
            );
        } else if (delegatorIndex == 3) {
            delegatorParams = abi.encode(
                IOperatorNetworkSpecificDelegator.InitParams({
                    baseParams: IBaseDelegator.BaseParams({
                        defaultAdminRoleHolder: owner,
                        hook: hook,
                        hookSetRoleHolder: owner
                    }),
                    network: network,
                    operator: owner
                })
            );
        }

        bytes memory slasherParams;
        if (slasherIndex == 0) {
            slasherParams = abi.encode(
                ISlasher.InitParams({
                    baseParams: IBaseSlasher.BaseParams({
                        isBurnerHook: burner != address(0)
                    })
                })
            );
        } else if (slasherIndex == 1) {
            slasherParams = abi.encode(
                IVetoSlasher.InitParams({
                    baseParams: IBaseSlasher.BaseParams({
                        isBurnerHook: burner != address(0)
                    }),
                    vetoDuration: vetoDuration,
                    resolverSetEpochsDelay: 3
                })
            );
        }

        (
            address vault_,
            address delegator_,
            address slasher_
        ) = IVaultConfigurator(vaultConfigurator).create(
                IVaultConfigurator.InitParams({
                    version: 2,
                    owner: owner,
                    vaultParams: vaultParams,
                    delegatorIndex: delegatorIndex,
                    delegatorParams: delegatorParams,
                    withSlasher: withSlasher,
                    slasherIndex: slasherIndex,
                    slasherParams: slasherParams
                })
            );

        // set network limit with deployer
        // TODO: set network limit once network has set max network limit
        // bytes32 subnetwork = Subnetwork.subnetwork(network, 0);
        // IFullRestakeDelegator(delegator_).setNetworkLimit(
        //     subnetwork,
        //     networkLimit
        // );

        // // renounce network limit role from deployer
        // bytes32 role = IFullRestakeDelegator(delegator_)
        //     .NETWORK_LIMIT_SET_ROLE();
        // AccessControlUpgradeable(delegator_).renounceRole(role, deployer);

        vm.stopBroadcast();

        console2.log("Vault: ", vault_);
        console2.log("Delegator: ", delegator_);
        console2.log("Slasher: ", slasher_);
    }
}
