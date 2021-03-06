pragma solidity >=0.6.0 <0.7.0;

contract Controlled {
    event NewController(address controller);
    /// @notice The address of the controller is the only address that can call
    ///  a function with this modifier
    modifier onlyController {
        require(msg.sender == controller, "Unauthorized");
        _;
    }

    address payable public controller;

    constructor() internal {
        controller = msg.sender;
    }

    /// @notice Changes the controller of the contract
    /// @param _newController The new controller of the contract
    function changeController(address payable _newController) public onlyController {
        controller = _newController;
        emit NewController(_newController);
    }
}
