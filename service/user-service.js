const UserModel = require("../models/user-model");
const bcrypt = require("bcrypt");
const uuid = require("uuid");
// const MailService = require("./mail-service");

const UserDto = require("../dtos/user-dto");
const tokenService = require("./token-service");
const ApiError = require("../exceptions/api-error");
const userModel = require("../models/user-model");

class UserService {
  async registration(email, password) {
    const candidate = await UserModel.findOne({ email });
    if (candidate) {
      throw ApiError.BedRequest(`user ${email} is 
      registered already`);
    }
    const hashPassword = await bcrypt.hash(password, 3);
    const activationLink = await uuid.v4();
    const user = await UserModel.create({
      email,
      password: hashPassword,
      activationLink,
    });
    // await MailService.sendActivationMail(
    //   email,
    //   `${process.env.API_URL}/api/activate/${activationLink}`
    // );

    const userDto = new UserDto(user); // id, email, isActivated
    const tokens = await tokenService.generateTokens({ ...userDto });
    await tokenService.saveToken(userDto.id, tokens.refreshToken);

    return {
      ...tokens,
      user: userDto,
    };
  }
  async activate(activationLink) {
    console.log(activationLink);

    const user = await UserModel.findOne({ activationLink });
    if (!user) {
      throw ApiError.BadRequest("incorrect activation link");
    }

    user.isActivated = true;
    await user.save();
  }
  async login(email, password) {
    const user = await UserModel.findOne({ email });
    if (!user) {
      throw ApiError.BadRequest("User not found with this email");
    }
    const isPassEquals = await bcrypt.compare(password, user.password);
    if (!isPassEquals) {
      throw ApiError.BadRequest("Incorrect password");
    }
    const userDto = new UserDto(user);
    const tokens = tokenService.generateTokens({ ...userDto });

    await tokenService.saveToken(userDto.id, tokens.refreshToken);
    return { ...tokens, user: userDto };
  }
  async logout(refreshToken) {
    const token = await tokenService.removeToken(refreshToken);
    return token;
  }
  async refresh(refreshToken) {
    console.log(refreshToken);
    if (!refreshToken) {
      throw ApiError.UnauthorizedError();
    }

    const userData = await tokenService.validateRefreshToken(refreshToken);
    const tokenFromDb = await tokenService.findToken(refreshToken);
    if (!userData || !tokenFromDb) {
      throw ApiError.UnauthorizedError();
    }

    if (refreshToken != tokenFromDb) {
      throw ApiError.UnauthorizedError();
    }

    console.log(userData);
    const user = await UserModel.findById(userData.id);

    const userDto = new UserDto(user); // id, email, isActivated
    const tokens = await tokenService.generateTokens({ ...userDto });
    await tokenService.saveToken(userDto.id, tokens.refreshToken);

    return {
      ...tokens,
      user: userDto,
    };
  }

  async getAllUsers() {
    const users = await UserModel.find();
    return users;
  }
}

module.exports = new UserService();
