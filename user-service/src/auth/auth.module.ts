import {Module} from '@nestjs/common';
import {MongooseModule} from '@nestjs/mongoose';
import {AuthService} from './auth.service';
import {AuthController} from './auth.controller';
import {User, UserSchema} from '../user/user.schema';
import {JwtModule} from '@nestjs/jwt';

@Module({
    imports: [
        MongooseModule.forFeature([{name: User.name, schema: UserSchema}]),
        JwtModule.register({
            secret: process.env.JWT_SECRET,
            signOptions: {expiresIn: '1h'}
        })
    ],
    controllers: [AuthController],
    providers: [AuthService]
})
export class AuthModule {}
