// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IVaultStorage} from "src/interfaces/IVaultStorage.sol";

interface IVault is IVaultStorage {
    error InvalidEpochDuration();
    error InvalidSlashDuration();
    error NotNetworkMiddleware();
    error NotWhitelistedDepositor();
    error InsufficientDeposit();
    error InsufficientWithdrawal();
    error TooMuchWithdraw();
    error InvalidEpoch();
    error InsufficientClaim();
    error InsufficientSlash();
    error OperatorNotOptedInNetwork();
    error SlashRequestNotExist();
    error VetoPeriodNotEnded();
    error SlashPeriodEnded();
    error SlashCompleted();
    error NotResolver();
    error VetoPeriodEnded();
    error InvalidAdminFee();
    error NotNetwork();
    error NotOperator();
    error NetworkNotOptedInVault();
    error ExceedsMaxNetworkLimit();
    error OperatorNotOptedInVault();
    error AlreadySet();
    error NoDepositWhitelist();

    /**
     * @notice Initial parameters needed for a vault deployment.
     * @param owner owner of the vault (can set metadata and enable/disable deposit whitelist)
     * The metadata should contain: name, description, external_url, image.
     * @param collateral underlying vault collateral
     * @param epochDuration duration of an vault epoch
     * @param vetoDuration duration of the veto period for a slash request
     * @param slashDuration duration of the slash period for a slash request (after veto period)
     * @param adminFee admin fee (up to ADMIN_FEE_BASE inclusively)
     * @param depositWhitelist enable/disable deposit whitelist
     */
    struct InitParams {
        address owner;
        address collateral;
        uint48 epochDuration;
        uint48 vetoDuration;
        uint48 slashDuration;
        uint256 adminFee;
        bool depositWhitelist;
    }

    /**
     * @notice Emitted when a deposit is made.
     * @param depositor account that made the deposit
     * @param onBehalfOf account that the deposit was made on behalf of
     * @param amount amount of the collateral deposited
     * @param shares amount of the active supply shares minted
     */
    event Deposit(address indexed depositor, address indexed onBehalfOf, uint256 amount, uint256 shares);

    /**
     * @notice Emitted when a withdrawal is made.
     * @param withdrawer account that made the withdrawal
     * @param claimer account that need to claim the withdrawal
     * @param amount amount of the collateral withdrawn
     * @param burnedShares amount of the active supply shares burned
     * @param mintedShares amount of the epoch withdrawal shares minted
     */
    event Withdraw(
        address indexed withdrawer, address indexed claimer, uint256 amount, uint256 burnedShares, uint256 mintedShares
    );

    /**
     * @notice Emitted when a claim is made.
     * @param claimer account that made the claim
     * @param recipient account that received the collateral
     * @param amount amount of the collateral claimed
     */
    event Claim(address indexed claimer, address indexed recipient, uint256 amount);

    /**
     * @notice Emitted when a slash request is made.
     * @param slashIndex index of the slash request
     * @param network network which requested the slash
     * @param resolver resolver which can veto the slash
     * @param operator operator which could be slashed
     * @param slashAmount maximum amount of the collateral to be slashed
     * @param vetoDeadline deadline for the resolver to veto the slash
     * @param slashDeadline deadline to execute slash
     */
    event RequestSlash(
        uint256 indexed slashIndex,
        address indexed network,
        address resolver,
        address indexed operator,
        uint256 slashAmount,
        uint48 vetoDeadline,
        uint48 slashDeadline
    );

    /**
     * @notice Emitted when a slash request is executed.
     * @param slashIndex index of the slash request
     * @param slashedAmount amount of the collateral slashed
     */
    event ExecuteSlash(uint256 indexed slashIndex, uint256 slashedAmount);

    /**
     * @notice Emitted when a slash request is vetoed.
     * @param slashIndex index of the slash request
     */
    event VetoSlash(uint256 indexed slashIndex);

    /**
     * @notice Emitted when a maximum network limit is set.
     * @param network network for which the maximum limit is set
     * @param resolver resolver for which the maximum limit is set
     * @param amount maximum possible amount of the collateral that can be slashed
     */
    event SetMaxNetworkLimit(address indexed network, address indexed resolver, uint256 amount);

    /**
     * @notice Emitted when an admin fee is set.
     * @param adminFee admin fee
     */
    event SetAdminFee(uint256 adminFee);

    /**
     * @notice Emitted when deposit whitelist status is set.
     * @param depositWhitelist enable/disable deposit whitelist
     */
    event SetDepositWhitelist(bool depositWhitelist);

    /**
     * @notice Emitted when a depositor whitelist status is set.
     * @param account account for which the whitelist status is set
     * @param value whitelist status
     */
    event SetDepositorWhitelistStatus(address indexed account, bool value);

    /**
     * @notice Emitted when a network limit is set.
     * @param network network for which the limit is set
     * @param resolver resolver for which the limit is set
     * @param amount amount of the collateral that can be slashed
     */
    event SetNetworkLimit(address indexed network, address indexed resolver, uint256 amount);

    /**
     * @notice Emitted when an operator limit is set.
     * @param operator operator for which the limit is set
     * @param network network for which the limit is set
     * @param amount amount of the collateral that can be slashed
     */
    event SetOperatorLimit(address indexed operator, address indexed network, uint256 amount);

    /**
     * @notice Get a total amount of the collateral deposited in the vault.
     * @return total amount of the collateral deposited
     */
    function totalSupply() external view returns (uint256);

    /**
     * @notice Get an active balance for a particular account at a given timestamp.
     * @param account account to get the active balance for
     * @param timestamp time point to get the active balance for the account at
     * @return active balance for the account at the timestamp
     */
    function activeBalanceOfAt(address account, uint48 timestamp) external view returns (uint256);

    /**
     * @notice Get an active balance for a particular account.
     * @param account account to get the active balance for
     * @return active balance for the account
     */
    function activeBalanceOf(address account) external view returns (uint256);

    /**
     * @notice Get a withdrawals balance for a particular account at a given epoch.
     * @param epoch epoch to get the withdrawals balance for the account at
     * @param account account to get the withdrawals balance for
     * @return withdrawals balance for the account at the epoch
     */
    function withdrawalsBalanceOf(uint256 epoch, address account) external view returns (uint256);

    /**
     * @notice Get a maximum amount of collateral that can be slashed for particular network, resolver and operator.
     * @param network address of the network
     * @param resolver address of the resolver
     * @param operator address of the operator
     * @return maximum amount of the collateral that can be slashed
     */
    function maxSlash(address network, address resolver, address operator) external view returns (uint256);

    /**
     * @notice Get a network limit for a particular network and resolver.
     * @param network address of the network
     * @param resolver address of the resolver
     * @return network limit
     */
    function networkLimit(address network, address resolver) external view returns (uint256);

    /**
     * @notice Get an operator limit for a particular operator and network.
     * @param operator address of the operator
     * @param network address of the network
     * @return operator limit
     */
    function operatorLimit(address operator, address network) external view returns (uint256);

    /**
     * @notice Deposit collateral into the vault.
     * @param onBehalfOf account that the deposit is made on behalf of
     * @param amount amount of the collateral to deposit
     * @return shares amount of the active supply shares minted
     */
    function deposit(address onBehalfOf, uint256 amount) external returns (uint256 shares);

    /**
     * @notice Withdraw collateral from the vault.
     * @param claimer account that needs to claim the withdrawal
     * @param amount amount of the collateral to withdraw
     * @return burnedShares amount of the active supply shares burned
     * @return mintedShares amount of the epoch withdrawal shares minted
     */
    function withdraw(address claimer, uint256 amount) external returns (uint256 burnedShares, uint256 mintedShares);

    /**
     * @notice Claim collateral from the vault.
     * @param recipient account that receives the collateral
     * @param epoch epoch to claim the collateral for
     * @return amount amount of the collateral claimed
     */
    function claim(address recipient, uint256 epoch) external returns (uint256 amount);

    /**
     * @notice Request a slash for a particular network, resolver and operator.
     * @param network address of the network
     * @param resolver address of the resolver
     * @param operator address of the operator
     * @param amount maximum amount of the collateral to be slashed
     * @return slashIndex index of the slash request
     * @dev Only network middleware can call this function.
     */
    function requestSlash(
        address network,
        address resolver,
        address operator,
        uint256 amount
    ) external returns (uint256 slashIndex);

    /**
     * @notice Execute a slash with a given slash index.
     * @param slashIndex index of the slash request
     * @return slashedAmount amount of the collateral slashed
     */
    function executeSlash(uint256 slashIndex) external returns (uint256 slashedAmount);

    /**
     * @notice Veto a slash with a given slash index.
     * @param slashIndex index of the slash request
     */
    function vetoSlash(uint256 slashIndex) external;

    /**
     * @notice Set a maximum network limit.
     * @param resolver address of the resolver
     * @param amount maximum amount of the collateral that can be slashed
     * @dev Only network can call this function.
     */
    function setMaxNetworkLimit(address resolver, uint256 amount) external;

    /**
     * @notice Set an admin fee.
     * @param adminFee admin fee (up to ADMIN_FEE_BASE inclusively)
     * @dev Only ADMIN_FEE_SET_ROLE holder can call this function.
     */
    function setAdminFee(uint256 adminFee) external;

    /**
     * @notice Enable/disable deposit whitelist.
     * @param status enable/disable deposit whitelist
     * @dev Only DEPOSIT_WHITELIST_SET_ROLE holder can call this function.
     */
    function setDepositWhitelist(bool status) external;

    /**
     * @notice Set a depositor whitelist status.
     * @param account account for which the whitelist status is set
     * @param status whitelist status
     * @dev Only DEPOSITOR_WHITELIST_ROLE holder can call this function.
     */
    function setDepositorWhitelistStatus(address account, bool status) external;

    /**
     * @notice Set a network limit for a particular network and resolver.
     * @param network address of the network
     * @param resolver address of the resolver
     * @param amount maximum amount of the collateral that can be slashed
     * @dev Only NETWORK_LIMIT_SET_ROLE holder can call this function.
     */
    function setNetworkLimit(address network, address resolver, uint256 amount) external;

    /**
     * @notice Set an operator limit for a particular operator and network.
     * @param operator address of the operator
     * @param network address of the network
     * @param amount maximum amount of the collateral that can be slashed
     * @dev Only OPERATOR_LIMIT_SET_ROLE holder can call this function.
     */
    function setOperatorLimit(address operator, address network, uint256 amount) external;
}
