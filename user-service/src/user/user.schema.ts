import {Schema, Prop, SchemaFactory} from '@nestjs/mongoose';
import {Document} from 'mongoose';

@Schema()
export class User extends Document {
    @Prop({required: true})
    name: string;

    @Prop({required: true, unique: true})
    phone: string;

    @Prop({required: true})
    password: string;

    @Prop()
    otpcode?: string;

    @Prop()
    otpcode_expiry?: Date;

    @Prop({default: false})
    isPhoneVerified: boolean;

    @Prop({default: false})
    isDriver: boolean;

    @Prop({default: false})
    isActive: boolean;
}

export const UserSchema = SchemaFactory.createForClass(User);